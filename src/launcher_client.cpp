#include <cstring>
#include <csignal>
#include <vector>
#include "networking_ssl.h"
#include "networking_tcp.h"
#include "iostream"
#include "cloud_common.h"
#include "cloud_client.h"
#include "client_shell.h"


static const std::string OPTION_LONG_PORT = "port=";

std::string prompt_password(const std::string &prompt) {
    std::cout << prompt;
    std::cout << "\x1B[37m\x1B[47m\x1B[8m";
    std::string password;
    std::getline(std::cin, password);
    std::cout << "\x1B[0m";
    std::cout.flush();
    return password;
}

int main(int argc, const char **argv) {
    signal(SIGPIPE, SIG_IGN);
    std::vector<std::string> args, options_long;
    std::string options_short;
    for (const char **arg = argv + 1; arg < argv + argc; arg++) {
        std::string s(*arg);
        if (s.find("--") == 0) {
            options_long.push_back(s.substr(2));
        } else if (s.find("-") == 0) {
            options_short += s.substr(1);
        } else {
            args.push_back(s);
        }
    }
    if (args.empty() || args[0].empty()) {
        std::cerr << "No target specified" << std::endl;
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
    bool registration = false;
    uint16_t port = CLOUD_DEFAULT_PORT;
    for (char o : options_short) {
        if (o == 'r') {
            registration = true;
        } else {
            std::cerr << "Unknown short option '" << o << "'" << std::endl;
            return 1;
        }
    }
    for (std::string &o : options_long) {
        if (o.empty()) continue;
        if (o.find(OPTION_LONG_PORT) == 0) {
            std::string s_port = o.substr(OPTION_LONG_PORT.length());
            int i_port = std::stoi(s_port);
            if (i_port > int(uint16_t(-1))) {
                std::cerr << "Port number is too large" << std::endl;
                return 1;
            }
            if (i_port < 0) {
                std::cerr << "Port number is too small" << std::endl;
                return 1;
            }
            port = i_port;
        } else {
            std::cerr << "Unknown long option '" << o << "'" << std::endl;
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
    int result;
    CloudClient *client = nullptr;
    if (registration) {
        std::cout << "Registering " << login << " at " << host << std::endl;
        try {
            client = new CloudClient(connection, login,
                                     []() -> std::string {
                                         std::cout << "Enter your invitation code: ";
                                         std::string invite;
                                         if (!std::getline(std::cin, invite)) {
                                             std::cout << std::endl << "Cancelled.";
                                             exit(0);
                                         }
                                         return invite;
                                     },
                                     []() -> std::string {
                                         std::string password1, password2;
                                         do {
                                             password1 = prompt_password("Enter new password: ");
                                             password2 = prompt_password("Confirm the password: ");
                                         } while (password1 != password2);
                                         return password1;
                                     });
        } catch (std::exception &exception) {
            std::cerr << "Registering failed: " << exception.what() << std::endl;
            connection->close();
            delete connection;
            return 1;
        }
    } else {
        std::string prompt = "Password for " + login + "@" + host + ": ";
        try {
            client = new CloudClient(connection, login, [prompt]() -> std::string {
                return prompt_password(prompt);
            });
        } catch (std::exception &exception) {
            std::cerr << "Authentication failed: " << exception.what() << std::endl;
            connection->close();
            delete connection;
            return 1;
        }
    }
    result = shell(client, connection, login, host);
    delete client;
    connection->close();
    delete connection;
    return result;
}
