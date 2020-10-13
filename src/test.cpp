#include <iostream>
#include <unistd.h>
#include <csignal>
#include "networking_tcp.h"
#include "server_config.h"
#include "cloud_server.h"
#include "cloud_client.h"

#define TEST_CLOUD_FILE "test_cloud.tar"
#define TEST_CLOUD_DIR "test_cloud"

bool unpack_test_cloud() {
    return !system("bash -c \"tar -xf " TEST_CLOUD_FILE "\"");
}

TCPServer *tcp_server = nullptr;
CloudServer *cloud_server = nullptr;

#define TEST_SERVER_PORT 1999
#define TEST_SERVER_USER "user"
#define TEST_SERVER_PASS "password"
#define TEST_SERVER_USER1 "alice"
#define TEST_SERVER_PASS1 "i_am_alice"
#define TEST_SERVER_USER2 "bob"
#define TEST_SERVER_PASS2 "b0b$12345"

void start_test_server() {
    chdir(TEST_CLOUD_DIR);
    LauncherConfig config;
    load_config(config);
    tcp_server = new TCPServer(TEST_SERVER_PORT);
    cloud_server = new CloudServer(tcp_server, config);
}


std::pair<NetConnection *, CloudClient *> connect_test_client(const std::string &login = TEST_SERVER_USER,
                                                              const std::string &pass = TEST_SERVER_PASS) {
    auto *connection = new TCPConnection("localhost", TEST_SERVER_PORT);
    auto *client = new CloudClient(connection, login, [&pass]() { return pass; });
    return {connection, client};
}

void cleanup() {
    delete cloud_server;
    delete tcp_server;
    system("bash -c \"rm -rf " TEST_CLOUD_DIR "\"");
}

#define SIMPLE_TEST_INIT() if (!unpack_test_cloud()) return false; start_test_server(); auto[connection, client] = connect_test_client()
#define SIMPLE_TEST_CLEANUP() delete client; delete connection; cleanup();

bool test_make_node(int, char **) {
    SIMPLE_TEST_INIT();
    uint8_t type = std::rand() % 2;
    Node node = client->make_node(client->get_home(), "make_node_test", type);
    bool ok = client->get_node_info(node).type == type;
    SIMPLE_TEST_CLEANUP();
    return ok;
}

bool test_homes(int, char **) {
    SIMPLE_TEST_INIT();
    Node home = client->get_home();
    Node home0 = client->get_home(TEST_SERVER_USER);
    if (home != home0) return false;
    if (client->get_parent(home, nullptr)) return false;
    if (client->get_node_owner(home) != TEST_SERVER_USER) return false;
    Node home1 = client->get_home(TEST_SERVER_USER1);
    if (client->get_parent(home1, nullptr)) return false;
    if (client->get_node_owner(home1) != TEST_SERVER_USER1) return false;
    Node home2 = client->get_home(TEST_SERVER_USER2);
    if (client->get_parent(home2, nullptr)) return false;
    if (client->get_node_owner(home2) != TEST_SERVER_USER2) return false;
    SIMPLE_TEST_CLEANUP();
    return true;
}

bool test_dirs(int, char **) {
    SIMPLE_TEST_INIT();
    Node home = client->get_home();
    Node dir = client->make_node(home, "dir_test", NODE_TYPE_DIRECTORY);
    size_t count = 0;
    client->list_directory(dir, [&count](std::string name, Node child) { count++; });
    if (count) return false;
    std::set<std::pair<std::string, uint8_t>> new_children;
    std::string charset = LOGIN_CHARSET; // using login charset here as it's enough for testing
    for (size_t i = 0; i < std::rand() % 20; i++) {
        size_t n = std::rand() % 255 + 1;
        char *name = new char[n + 1];
        for (size_t j = 0; j < n; j++) {
            size_t k = std::rand() % charset.length();
            name[j] = charset[k];
        }
        name[n] = '\0';
        new_children.insert({name, std::rand() % 2});
    }
    for (auto[name, type] : new_children) {
        client->make_node(dir, name, type);
    }
    std::set<std::pair<std::string, uint8_t>> cur_children;
    {
        CloudClient *client1 = client;
        client->list_directory(dir, [client1, &cur_children](std::string name, Node child) {
            cur_children.insert({name, client1->get_node_info(child).type});
        });
    }
    bool ok = new_children == cur_children;
    SIMPLE_TEST_CLEANUP();
    return ok;
}

bool test_groups(int, char **) {
    SIMPLE_TEST_INIT();
    size_t count = 0;
    client->group_list([&count](const std::string &) {
        count++;
    });
    if (count) return false;
    auto[connection1, client1] = connect_test_client(TEST_SERVER_USER1, TEST_SERVER_PASS1);
    client1->group_invite(TEST_SERVER_USER);
    count = 0;
    bool ok = false;
    client->group_list([&count, &ok](const std::string &group) {
        count++;
        if (group == TEST_SERVER_USER1) ok = true;
    });
    if (count != 1 || !ok) return false;
    auto[connection2, client2] = connect_test_client(TEST_SERVER_USER2, TEST_SERVER_PASS2);
    client2->group_invite(TEST_SERVER_USER);
    delete client2;
    delete connection2;
    count = 0;
    bool ok1 = false;
    bool ok2 = false;
    client->group_list([&count, &ok1, &ok2](const std::string &group) {
        count++;
        if (group == TEST_SERVER_USER1) ok1 = true;
        if (group == TEST_SERVER_USER2) ok2 = true;
    });
    if (count != 2 || !ok1 || !ok2) return false;
    client1->group_kick(TEST_SERVER_USER);
    delete client1;
    delete connection1;
    count = 0;
    ok = false;
    client->group_list([&count, &ok](const std::string &group) {
        count++;
        if (group == TEST_SERVER_USER2) ok = true;
    });
    if (count != 1 && !ok) return false;
    SIMPLE_TEST_CLEANUP();
    return true;
}

bool test_tokens(int, char **) {
    SIMPLE_TEST_INIT();
    {
        CloudClient client1 = *client;
    }
    SIMPLE_TEST_CLEANUP();
    return true;
}

std::map<std::string, std::function<bool(int, char **)>> tests{
        {"make_node", test_make_node},
        {"homes",     test_homes},
        {"dirs",      test_dirs},
        {"groups",    test_groups},
        {"tokens",    test_tokens}
};

int main(int argc, char **argv) {
    std::srand(std::time(nullptr));
    signal(SIGPIPE, SIG_IGN);
    if (chdir("../testing")) return 1;
    if (argc == 0 || tests.find(argv[1]) == tests.end()) {
        std::cerr << "invalid test name" << std::endl;
        return 1;
    } else return !tests[argv[1]](argc - 1, argv + 2);
}