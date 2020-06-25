#ifndef CLOUD9_CLOUD_SERVER_H
#define CLOUD9_CLOUD_SERVER_H

#include <string>
#include <thread>
#include <vector>
#include <set>
#include "networking.h"
#include "cloud_common.h"

class CloudConfig {
public:
    std::string users_directory;
    std::string nodes_head_directory;
    std::string nodes_data_directory;

    CloudConfig();

    ~CloudConfig();
};

typedef struct {
    bool read = false, write = false;
} ReadWrite;

class CloudServer final {
private:
    class Session {
    public:
        NetConnection *const connection;
        std::string login;

        explicit Session(NetConnection *connection);
    };

private:
    const CloudConfig config;
    NetServer *const net;
    std::thread *connector;
    std::vector<std::thread *> listeners;
    std::set<Session *> sessions;
    bool shutting_down = false;

    void connector_routine();

    void listener_routine(Session *);

    std::pair<char *, size_t> get_node_head(Node node);

    ReadWrite get_user_rights(Node node, const std::string &user);

    std::string get_node_data_path(Node node);

    bool get_parent(Node node, Node &parent, uint16_t &error);

    bool get_home_owner(Node node, uint16_t &error, std::string &owner);

public:
    CloudServer(NetServer *net, const CloudConfig &config);

    void wait_destroy();

    ~CloudServer();
};

#endif //CLOUD9_CLOUD_SERVER_H
