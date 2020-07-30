#include <stdexcept>
#include <iostream>
#include <cstring>
#include <csignal>
#include <filesystem>
#include <fstream>

extern "C" {
#include "lua.h"
}

#include "networking_ssl.h"
#include "networking_tcp.h"
#include "cloud_server.h"
#include "server_config.h"

NetConnection *connection = nullptr;
CloudServer *server = nullptr;

void server_shutdown() {
    delete server;
    delete connection;
    if (!server) std::cout << "warning: server wasn't started" << std::endl;
}

int main(int argc, const char **argv) {
    std::cout << "cloud9 version " << CLOUD9_REL_NAME << " (" << CLOUD9_REL_CODE << ")" << std::endl;
    std::srand(std::time(nullptr));
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, [](int) {
        std::cout << "received SIGTERM, stopping server..." << std::endl;
        server_shutdown();
        std::cout << "server stopped, exiting normally..." << std::endl;
        exit(0);
    });
    signal(SIGINT, [](int) {
        std::cout << "received SIGINT, stopping server..." << std::endl;
        server_shutdown();
        std::cout << "server stopped, exiting normally..." << std::endl;
        exit(0);
    });
    LauncherConfig config;
    try {
        load_config(config);
    } catch (std::exception &exception) {
        std::cerr << "failed to load configuration file: " << exception.what() << std::endl;
        return 1;
    }
    NetServer *net;
    try {
        if (config.ssl) {
            bool password_prompt = config.ssl_password.empty();
            void *ud = password_prompt ? nullptr : &config;
            int (*callback_prompt)(char *, int, int, void *) = [](char *buf, int size, int rw, void *ud) -> int {
                auto passwd = prompt_password("Enter PEM password: ");
                std::strcpy(buf, passwd.c_str());
                return passwd.length();
            };
            int (*callback_no_prompt)(char *, int, int, void *) = [](char *buf, int size, int rw, void *ud) -> int {
                auto *config = reinterpret_cast<LauncherConfig *>(ud);
                std::strcpy(buf, config->ssl_password.c_str());
                return config->ssl_password.length();
            };
            auto callback = password_prompt ? callback_prompt : callback_no_prompt;
            net = new SSLServer(config.server_port, config.ssl_cert_path.c_str(), config.ssl_key_path.c_str(), callback,
                                ud);
        } else {
            net = new TCPServer(config.server_port);
        }
    } catch (std::exception &exception) {
        std::cerr << "failed to start server: " << exception.what() << std::endl;
        return 1;
    }
    server = new CloudServer(net, config);
    server->wait_destroy();
    return 0;
}

