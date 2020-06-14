#ifndef CLOUD9_CLOUD_SERVER_H
#define CLOUD9_CLOUD_SERVER_H

#include <string>
#include <thread>
#include <vector>
#include <set>
#include "networking.h"
#include "cloud_common.h"

class CloudConfig final {
public:
    std::string users_directory;
    std::string nodes_head_directory;
    std::string nodes_data_directory;

    CloudConfig();

    ~CloudConfig();
};

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

    std::string get_node_data_path(Node node);
public:
    CloudServer(NetServer *net, const CloudConfig& config);

    void wait_destroy();

    ~CloudServer();
};

#endif //CLOUD9_CLOUD_SERVER_H
