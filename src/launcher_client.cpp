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

int main(int argc, const char **argv) {
    signal(SIGPIPE, [](int) {});
    if (argc != 3 && argc != 4) {
        std::cerr << "invalid number of arguments" << std::endl;
        return 1;
    }
    NetConnection *connection = nullptr;
    try {
        connection = new TCPConnection(argv[1], atoi(argv[2]));
    } catch (std::exception &exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }
    if (argc == 3) {
        std::cerr << "not implemented yet" << std::endl;
        connection->close();
        delete connection;
        return 1;
    } else {
        std::string login = argv[3];
        std::string host = argv[1];
        std::string port = argv[2];
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

        std::map<std::string, void (*)(CloudClient *, Node &, std::vector<std::string> &)> commands;
        {
            commands["ls"] = [](CloudClient *client, Node &cwd, std::vector<std::string> &args) {
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
            };
        }

        Node cwd = client->get_home(argv[3]);
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
                    if (commands.contains(command_name)) {
                        try {
                            commands[command_name](client, cwd, command_store);
                        } catch (std::runtime_error &error) {
                            std::cerr << "error: " << error.what() << std::endl;
                        }
                    } else std::cerr << "no such command: " << command_name << std::endl;
                }
            } else std::cerr << "failed to parse command: " << error << std::endl;
            if(!connection->is_valid()) {
                std::cerr << "Connection lost, exiting" << std::endl;
                fail = true;
                break;
            }
        }
        delete client;
        connection->close();
        delete connection;
        if(fail) return 1;
    }
}
