#include <iostream>
#include <unistd.h>
#include <csignal>
#include "networking_tcp.h"
#include "server_config.h"
#include "cloud_server.h"
#include "cloud_client.h"

#define TEST_CLOUD_FILE "test_cloud.tar"
#define TEST_CLOUD_DIR "test_cloud"
#define TEST_CLOUD_CONFIG "config.lua"

bool unpack_test_cloud() {
    return !system("bash -c \"tar -xf " TEST_CLOUD_FILE "\"");
}

TCPServer *tcp_server = nullptr;
CloudServer *cloud_server = nullptr;

#define TEST_SERVER_PORT 1999
#define TEST_SERVER_USER "user"
#define TEST_SERVER_PASS "password"

void start_test_server() {
    LauncherConfig config;
    load_config(TEST_CLOUD_DIR "/" TEST_CLOUD_CONFIG, config);
    tcp_server = new TCPServer(TEST_SERVER_PORT);
    cloud_server = new CloudServer(tcp_server, config);
}


std::pair<NetConnection *, CloudClient *> connect_test_client() {
    auto *connection = new TCPConnection("localhost", TEST_SERVER_PORT);
    auto *client = new CloudClient(connection, TEST_SERVER_USER, []() { return TEST_SERVER_PASS; });
    return {connection, client};
}

void cleanup() {
    delete cloud_server;
    delete tcp_server;
    system("bash -c \"rm -rf " TEST_CLOUD_DIR "\"");
}


bool mknod_test(int, char **) {
    if (!unpack_test_cloud()) return false;
    start_test_server();
    auto[connection, client] = connect_test_client();
    Node node = client->make_node(client->get_home(), "mknod_test", NODE_TYPE_DIRECTORY);
    bool ok = client->get_node_info(node).type == NODE_TYPE_DIRECTORY;
    delete client;
    delete connection;
    cleanup();
    return ok;
}

std::map<std::string, std::function<bool(int, char **)>> tests{
        {"mknod", mknod_test}
};

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (chdir("../testing")) return 1;
    if (argc == 0 || !tests.contains(argv[1])) {
        std::cerr << "invalid test name" << std::endl;
        return 1;
    } else return !tests[argv[1]](argc - 1, argv + 2);
}