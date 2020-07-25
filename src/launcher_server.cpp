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

CloudServer *server = nullptr;

void server_shutdown() {
    delete server;
    if (!server) std::cout << "warning: server wasn't started" << std::endl;
}

int main(int argc, const char **argv) {
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
    if (argc != 2) {
        std::cerr << "invalid number of arguments" << std::endl;
        return 1;
    }
    LauncherConfig config;
    try {
        load_config(argv[1], config);
    } catch (std::exception &exception) {
        std::cerr << "failed to load configuration file: " << exception.what() << std::endl;
        return 1;
    }
    NetServer *net;
    try {
        net = new TCPServer(config.server_port);
    } catch (std::exception &exception) {
        std::cerr << "failed to start server: " << exception.what() << std::endl;
        return 1;
    }
    server = new CloudServer(net, config);
    server->wait_destroy();
    return 0;
}

