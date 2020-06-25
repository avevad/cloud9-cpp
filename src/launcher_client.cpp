#include <cstring>
#include <csignal>
#include <vector>
#include <map>
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
        if (part.empty() || part == ".") continue;
        else if (part == "..") client->get_parent(current, &current, nullptr);
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

static const std::string OPTION_LONG_PORT = "port=";

int main(int argc, const char **argv) {
    const std::map<std::string, void (*)(CloudClient *, Node &, std::vector<std::string> &)> commands{
            {"ls",  [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (args.size() > 1) {
                    std::cerr << "too much arguments" << std::endl;
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
                } else std::cerr << "too much arguments" << std::endl;
            }},
            {"pwd", [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
                if (!args.empty()) std::cerr << "too much arguments" << std::endl;
                else {
                    std::cout << "#" << node2string(cwd) << std::endl;
                }
            }}
    };

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
    Node cwd = client->get_home(login);
    std::string command;
    std::vector<std::string> command_store;
    bool fail = false;
    while (true) {
        std::cout << login << "@" << host << "$ ";
        if (!std::getline(std::cin, command)) {
            std::cout << std::endl;
            std::cout << "Logout." << std::endl;
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
                    } catch (Cloud9RequestError &error) {
                        std::cerr << "request failed: " << error.what() << std::endl;
                    }
                } else std::cerr << "no such command: " << command_name << std::endl;
            }
        } else std::cerr << "failed to parse command: " << error << std::endl;
        if (!connection->is_valid()) {
            std::cerr << "Connection lost, exiting..." << std::endl;
            fail = true;
            break;
        }
    }
    delete client;
    connection->close();
    delete connection;
    if (fail) return 1;
}
