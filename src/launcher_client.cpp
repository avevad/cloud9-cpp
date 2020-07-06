#include <cstring>
#include <csignal>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include "networking_ssl.h"
#include "networking_tcp.h"
#include "iostream"
#include "cloud_common.h"
#include "cloud_client.h"

std::string parse_command(const std::string &command, std::vector<std::string> &store) {
    std::string current;
    bool slash = false;
    for (size_t pos = 0; pos < command.size(); pos++) {
        char c = command[pos];
        if (c == '\\') {
            if (slash) {
                current += "\\";
                slash = false;
            } else slash = true;
        } else if (c == ' ') {
            if (slash) {
                current += " ";
                slash = false;
            } else {
                if (!current.empty()) {
                    store.push_back(current);
                    current = "";
                }
            }
        } else {
            if (slash) {
                return std::string("unknown escape sequence: \\") + c;
            } else current += c;
        }
    }
    if (slash) return "unfinished escape sequence";
    if (!current.empty()) store.push_back(current);
    return "";
}

bool is_absolute_path(const std::string &path) {
    return path[0] == CLOUD_PATH_HOME || path[0] == CLOUD_PATH_NODE;
}

std::string get_absolute_path_base(const std::string &path) {
    return path.substr(0, path.find(CLOUD_PATH_DIV));
}

Node get_absolute_path_base_node(CloudClient *client, const std::string &base) {
    if (base[0] == CLOUD_PATH_NODE) {
        return string2node(base.substr(1));
    } else if (base[0] == CLOUD_PATH_HOME) {
        return client->get_home(base.substr(1));
    } else throw std::invalid_argument("invalid base " + base);
}

Node get_relative_path_node(CloudClient *client, Node base, const std::string &path) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t pos = 0; pos < path.length(); pos++) {
        if (path[pos] == '/') {
            parts.push_back(path.substr(start, pos - start));
            start = pos + 1;
        }
    }
    parts.push_back(path.substr(start, path.size()));
    Node current = base;
    for (const std::string &part : parts) {
        if (part.empty()) continue;
        else if (part == "..") client->get_parent(current, &current);
        else {
            bool found = false;
            client->list_directory(current, [&](const std::string &name, Node child) {
                if (name == part) {
                    found = true;
                    current = child;
                }
            });
            if (!found) throw std::runtime_error("'" + part + "' not found");
        }
    }
    return current;
}

Node get_path_node(CloudClient *client, Node cwd, const std::string &path) {
    if (is_absolute_path(path)) {
        std::string base = get_absolute_path_base(path);
        return get_relative_path_node(client, get_absolute_path_base_node(client, base), path.substr(base.length()));
    } else return get_relative_path_node(client, cwd, path);
}

std::string get_node_path(CloudClient *client, Node node) {
    Node parent;
    bool has_parent;
    try {
        has_parent = client->get_parent(node, &parent);
    } catch (CloudRequestError &error) {
        if (error.status == REQUEST_ERR_FORBIDDEN)
            return CLOUD_PATH_DIV + std::string(1, CLOUD_PATH_UNKNOWN);
        else throw;
    }
    if (has_parent) {
        std::string name;
        client->list_directory(parent, [&name, node](const std::string &child_name, Node child) {
            if (child == node)
                name = child_name;
        });
        return get_node_path(client, parent) + CLOUD_PATH_DIV + name;
    } else {
        return "";
    }
}

#define PROGRESSBAR_SIZE 20

void print_loading_status(size_t done, size_t all, size_t start_time) {
    size_t cur_time = get_current_time_ms();
    double seconds = double(cur_time - start_time) / 1000;
    size_t speed = double(done) / seconds;
    double part = (all == 0) ? 1 : (double(done) / double(all));
    size_t segments = part * PROGRESSBAR_SIZE;
    std::string progress = "[";
    for (size_t i = 0; i < segments; i++) progress += "=";
    for (size_t i = 0; i < PROGRESSBAR_SIZE - segments; i++) progress += " ";
    progress += "]";
    auto[done_h, done_p] = human_readable_size(done);
    auto[all_h, all_p] = human_readable_size(all);
    auto[speed_h, speed_p] = human_readable_size(speed);
    std::ostringstream out;
    out << std::fixed << std::setprecision(1);
    out << done_h << " " << done_p << "B";
    out << "/";
    out << all_h << " " << all_p << "B";
    out << " ";
    out << progress;
    out << " ";
    out << (part * 100);
    out << "% ";
    out << speed_h << " " << speed_p << "B";
    out << "/s ";
    out << human_readable_time((cur_time - start_time) / 1000) << "/";
    out << human_readable_time(all / (speed + 1));
    std::cout << "\r\033[K\033[1F\033[1E";
    std::cout << out.str();
    std::cout.flush();
}

#define STATUS_DELAY 500

void put_file(CloudClient *client, const std::string &src, Node dst, bool info, size_t block_size) {
    size_t size = std::filesystem::file_size(src);
    std::ifstream stream(src);
    auto fd = client->fd_open(dst, NODE_FD_MODE_WRITE);
    char *buffer = new char[block_size];
    size_t done = 0;
    auto start_time = get_current_time_ms();
    size_t last_status_time = start_time;
    try {
        while (!stream.eof()) {
            stream.read(buffer, block_size);
            size_t read = stream.gcount();
            done += read;
            client->fd_write(fd, read, buffer);
            if (info) {
                if (get_current_time_ms() - last_status_time > STATUS_DELAY) {
                    print_loading_status(done, size, start_time);
                    last_status_time = get_current_time_ms();
                }
            }
        }
    } catch (...) {
        delete[] buffer;
        throw;
    }
    if (info) print_loading_status(done, size, start_time);
    delete[] buffer;
    client->fd_close(fd);
    if (info) std::cout << std::endl;
}

void put_node(CloudClient *client, const std::string &file, Node dst_dir, bool info, size_t block_size, bool recursive,
              const std::string &dst_dir_path) {
    std::string name = std::filesystem::absolute(std::filesystem::path(file)).filename();
    if (std::filesystem::is_regular_file(file)) {
        if (info) std::cout << file << "\t-->\t" << dst_dir_path << name << std::endl;
        Node dst = client->make_node(dst_dir, name, NODE_TYPE_FILE);
        put_file(client, file, dst, info, block_size);
    } else if (std::filesystem::is_directory(file)) {
        if (recursive) {
            if (info) std::cout << "mkdir " << dst_dir_path << name << std::endl;
            Node dst = client->make_node(dst_dir, name, NODE_TYPE_DIRECTORY);
            for (const auto &child : std::filesystem::directory_iterator(file)) {
                put_node(client, child.path(), dst, info, block_size, recursive, dst_dir_path + name + CLOUD_PATH_DIV);
            }
        } else std::cout << "put: non-recursive, skipping directory " << file << std::endl;
    } else {
        std::cout << "put: skipping other file " << file << std::endl;
    }
}

void get_file(CloudClient *client, Node src, const std::string &dst, bool info, size_t block_size) {
    NodeInfo node_info = client->get_node_info(src);
    std::ofstream stream(dst);
    auto fd = client->fd_open(src, NODE_FD_MODE_READ);
    char *buffer = new char[block_size];
    size_t done = 0;
    auto start_time = get_current_time_ms();
    size_t last_status_time = start_time;
    try {
        while (true) {
            auto read = client->fd_read(fd, block_size, buffer);
            done += read;
            stream.write(buffer, read);
            if (info) {
                if (get_current_time_ms() - last_status_time > STATUS_DELAY) {
                    print_loading_status(done, node_info.size, start_time);
                    last_status_time = get_current_time_ms();
                }
            }
        }
    } catch (CloudRequestError &error) {
        if (error.status != REQUEST_ERR_END_OF_FILE) {
            delete[] buffer;
            throw;
        }
    } catch (...) {
        delete[] buffer;
        throw;
    }
    if (info) print_loading_status(done, node_info.size, start_time);
    delete[] buffer;
    client->fd_close(fd);
    if (info) std::cout << std::endl;
}

void get_node(CloudClient *client, Node node, const std::string &dst_dir, bool info, size_t block_size, bool recursive,
              const std::string &node_path, const std::string &node_name) {
    NodeInfo node_info = client->get_node_info(node);
    if (node_info.type == NODE_TYPE_FILE) {
        if (info) std::cout << dst_dir << node_name << "\t<--\t" << node_path << std::endl;
        if (std::filesystem::exists(dst_dir + node_name)) throw std::runtime_error("file exists");
        get_file(client, node, dst_dir + node_name, info, block_size);
    } else if (node_info.type == NODE_TYPE_DIRECTORY) {
        if (recursive) {
            if (info) std::cout << "mkdir " << dst_dir << node_name << std::endl;
            std::filesystem::create_directory(dst_dir + node_name);
            client->list_directory(node, [=](const std::string &child_name, Node child) {
                get_node(client, child, dst_dir + node_name + PATH_DIV, info, block_size, recursive,
                         node_path + CLOUD_PATH_DIV + child_name, child_name);
            });
        } else std::cout << "get: non-recursive, skipping directory " << node_path << std::endl;
    }
}

int shell(CloudClient *client, NetConnection *connection, const std::string &login, const std::string &host) {
    const std::map<std::string, void (*)(CloudClient *, Node &, std::vector<std::string> &)> commands{
            {"ls",  [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (args.size() > 1) {
                    std::cerr << "ls: too many arguments" << std::endl;
                    return;
                }
                std::string flags;
                if (!args.empty()) {
                    flags = args[0];
                }
                client->list_directory(cwd, [](const std::string &name, Node node) {
                    std::cout << name << std::endl;
                });
            }},
            {"cd",  [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (args.empty()) {
                    cwd = client->get_home();
                } else if (args.size() == 1) {
                    cwd = get_path_node(client, cwd, args[0]);
                } else std::cerr << "cd: too many arguments" << std::endl;
            }},
            {"pwd",   [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (!args.empty()) std::cerr << "pwd: too many arguments" << std::endl;
                else {
                    std::cout << CLOUD_PATH_HOME << client->get_node_owner(cwd) << get_node_path(client, cwd)
                              << std::endl;
                }
            }},
            {"mkdir", [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (args.empty()) std::cerr << "mkdir: not enough arguments" << std::endl;
                else if (args.size() == 1) {
                    std::string path = args[0];
                    auto i = path.find_last_of(CLOUD_PATH_DIV);
                    Node parent = cwd;
                    std::string name = path;
                    if (i != std::string::npos) {
                        parent = get_path_node(client, cwd, path.substr(0, i));
                        name = path.substr(i + 1);
                    }
                    client->make_node(parent, name, NODE_TYPE_DIRECTORY);
                } else std::cerr << "mkdir: too many arguments" << std::endl;
            }},
            {"node",  [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (args.empty()) std::cout << "#" << node2string(cwd) << std::endl;
                else if (args.size() == 1) {
                    std::string result = node2string(get_path_node(client, cwd, args[0]));
                    std::cout << "#" << result << std::endl;
                } else std::cerr << "node: too many arguments" << std::endl;
            }},
            {"put", [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                std::vector<std::string> options;
                std::vector<std::string> files;
                for (auto &arg : args) {
                    if (arg.starts_with("-")) options.push_back(arg.substr(1));
                    else files.push_back(arg);
                }
                bool info = true;
                size_t block_size = 1024 * 1024; // 1 MiB
                bool recursive = false;
                for (auto &option : options) {
                    if (option == "s") info = false;
                    else if (option == "r") recursive = true;
                    else if (option.starts_with("b=")) {
                        block_size = std::stoll(option.substr(2));
                    } else {
                        std::cerr << "put: unknown option " << option << std::endl;
                        return;
                    }
                }
                if (files.empty()) {
                    std::cerr << "put: no destination directory specified" << std::endl;
                    return;
                }
                std::string dst_dir_path = files.back();
                Node dst_dir = get_path_node(client, cwd, dst_dir_path);
                dst_dir_path = CLOUD_PATH_HOME + client->get_node_owner(dst_dir) + get_node_path(client, dst_dir) +
                               CLOUD_PATH_DIV;
                files.pop_back();
                if (files.empty()) {
                    std::cerr << "put: no source files given" << std::endl;
                    return;
                }
                for (auto &file : files) {
                    put_node(client, file, dst_dir, info, block_size, recursive, dst_dir_path);
                }
            }},
            {"get", [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                std::vector<std::string> options;
                std::vector<std::string> files;
                for (auto &arg : args) {
                    if (arg.starts_with("-")) options.push_back(arg.substr(1));
                    else files.push_back(arg);
                }
                bool info = true;
                size_t block_size = 1024 * 1024; // 1 MiB
                bool recursive = false;
                for (auto &option : options) {
                    if (option == "s") info = false;
                    else if (option == "r") recursive = true;
                    else if (option.starts_with("b=")) {
                        block_size = std::stoll(option.substr(2));
                    } else {
                        std::cerr << "get: unknown option " << option << std::endl;
                        return;
                    }
                }
                if (files.empty()) {
                    std::cerr << "get: no destination directory specified" << std::endl;
                    return;
                }
                std::string dst_dir = files.back();
                files.pop_back();
                if (files.empty()) {
                    std::cerr << "get: no source files given" << std::endl;
                    return;
                }
                for (auto &file : files) {
                    Node node = get_path_node(client, cwd, file);
                    std::string path = get_node_path(client, node);
                    std::string name;
                    if (path.size() <= 1) name = client->get_node_owner(node);
                    else name = path.substr(path.find_last_of(CLOUD_PATH_DIV) + 1);
                    get_node(client, node, dst_dir + PATH_DIV, info, block_size, recursive,
                             CLOUD_PATH_HOME + client->get_node_owner(node) + path, name);
                }
            }}
    };
    Node cwd = client->get_home(login);
    std::string command;
    std::vector<std::string> command_store;
    bool fail = false;
    while (true) {
        std::cout << login << "@" << host << "$ ";
        if (!std::getline(std::cin, command)) {
            std::cout << std::endl;
            std::cout << "logout, connection closed" << std::endl;
            break;
        }
        command_store.clear();
        std::string error = parse_command(command, command_store);
        if (error.empty()) {
            if (!command_store.empty()) {
                std::string command_name = command_store.front();
                command_store.erase(command_store.begin());
                if (commands.find(command_name) != commands.end()) {
                    try {
                        commands.at(command_name)(client, cwd, command_store);
                    } catch (std::runtime_error &error) {
                        std::cerr << "error: " << error.what() << std::endl;
                    } catch (CloudRequestError &error) {
                        std::cerr << "request failed: " << error.what() << std::endl;
                    }
                } else std::cerr << "no such command: " << command_name << std::endl;
            }
        } else std::cerr << "failed to parse command: " << error << std::endl;
        if (!connection->is_valid()) {
            std::cerr << "connection closed" << std::endl;
            fail = true;
            break;
        }
    }
    return fail;
}

static const std::string OPTION_LONG_PORT = "port=";

int main(int argc, const char **argv) {
    signal(SIGPIPE, [](int) {});
    std::vector<std::string> args, options_long;
    std::string options_short;
    for (const char **arg = argv + 1; arg < argv + argc; arg++) {
        std::string s(*arg);
        if (s.starts_with("--")) {
            options_long.push_back(s.substr(2));
        } else if (s.starts_with("-")) {
            options_short += s.substr(1);
        } else {
            args.push_back(s);
        }
    }
    if (args.empty() || args[0].empty()) {
        std::cerr << "no target specified" << std::endl;
        return 1;
    }
    std::string login;
    std::string host;
    { // parsing target
        std::string target = args[0];
        auto login_end = std::find(target.begin(), target.end(), LOGIN_DIV);
        size_t host_begin = 0;
        if (login_end == target.end()) {
            login = getenv("USER");
        } else {
            login = target.substr(0, login_end - target.begin());
            host_begin = login_end - target.begin() + 1;
        }
        host = target.substr(host_begin);
    }
    uint16_t port = CLOUD_DEFAULT_PORT;
    for (char o : options_short) {
        std::cerr << "unknown short option '" << o << "'" << std::endl;
        return 1;
    }
    for (std::string &o : options_long) {
        if (o.empty()) continue;
        if (o.starts_with(OPTION_LONG_PORT)) {
            std::string s_port = o.substr(OPTION_LONG_PORT.length());
            int i_port = std::stoi(s_port);
            if (i_port > int(uint16_t(-1))) {
                std::cerr << "port number is too large" << std::endl;
                return 1;
            }
            if (i_port < 0) {
                std::cerr << "port number is too small" << std::endl;
                return 1;
            }
            port = i_port;
        } else {
            std::cerr << "unknown long option '" << o << "'" << std::endl;
            return 1;
        }
    }
    NetConnection *connection = nullptr;
    try {
        connection = new TCPConnection(host.c_str(), port);
    } catch (std::exception &exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }
    std::string prompt = login + "@" + host + "'s password: ";
    int result;
    if (login.empty()) {
        std::cerr << "not implemented yet" << std::endl; // TODO: implement user registering
        result = 1;
    } else {
        CloudClient *client = nullptr;
        try {
            client = new CloudClient(connection, login, [](void *ud) -> std::string {
                const char *prompt = static_cast<const char *>(ud);
                std::cout << prompt;
                std::cout << "\x1B[37m\x1B[47m\x1B[8m";
                std::string password;
                std::getline(std::cin, password);
                std::cout << "\x1B[0m";
                return password;
            }, (void *) prompt.c_str());
        } catch (std::exception &exception) {
            std::cerr << "authentication failed: " << exception.what() << std::endl;
            connection->close();
            delete connection;
            return 1;
        }
        result = shell(client, connection, login, host);
        delete client;
    }
    connection->close();
    delete connection;
    return result;
}
