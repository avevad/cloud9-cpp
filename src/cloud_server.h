#ifndef CLOUD9_CLOUD_SERVER_H
#define CLOUD9_CLOUD_SERVER_H

#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <set>
#include <mutex>
#include <map>
#include "networking.h"
#include "cloud_common.h"

class CloudConfig {
public:
    std::string users_directory;
    std::string nodes_head_directory;
    std::string nodes_data_directory;
    std::string access_log;
    std::string invites_file;
    size_t data_buffer_size;
    size_t net_buffer_size;

    CloudConfig();

    ~CloudConfig();
};

struct ReadWrite {
    bool read = false, write = false;
};

class CloudServer final {
private:
    class Session {
    public:
        class FileDescriptor {
        public:
            Node node;
            uint8_t mode;
            std::fstream *stream;
        };

        NetConnection *const connection;
        std::string login;
        std::vector<FileDescriptor> fds;
        std::mutex lock;

        explicit Session(NetConnection *connection);
    };

private:
    const CloudConfig config;
    NetServer *const net;
    std::thread *connector;
    std::vector<std::thread *> listeners;
    std::set<Session *> sessions;
    bool shutting_down = false;
    std::mutex lock;
    std::map<Node, std::set<Session *>> readers;
    std::map<Node, Session *> writers;
    std::ofstream access_log;

    void connector_routine();

    void listener_routine(Session *);

    std::pair<char *, size_t> get_node_head(Node node);

    std::pair<char *, size_t> get_node_data(Node node); // use only for directories

    ReadWrite get_user_rights(Node node, const std::string &user);

    std::string get_node_data_path(Node node);

    std::string get_node_head_path(Node node);

    bool get_parent(Node node, Node &parent, uint16_t &error);

    bool get_home_owner(Node node, uint16_t &error, std::string &owner);

    Node generate_node();

    std::string get_node_owner(Node node);

    bool node_exists(Node node);

    void close_fd(Session *session, Session::FileDescriptor fd);

    std::string get_user_head_path(const std::string &user);

    std::pair<const char *, size_t> get_user_head(const std::string &user);

    bool is_member(const std::string &user, const std::string &group);

    std::string get_node_group(const char *node_head);

    void remove_from_group(const std::string &group, const std::string &user);

    std::pair<ssize_t, ssize_t> find_child_by_node(const char *dir_data, size_t dir_data_size, Node node);

    std::pair<ssize_t, ssize_t> find_child_by_name(const char *dir_data, size_t dir_data_size, const std::string &name);

    bool use_invite(const std::string &invite);

    static std::string log_pair_to_str(const std::pair<std::string, std::string> &p) {
        return p.first + "='" + p.second + "'";
    }

    template<typename... P>
    void log_request(Session *session, uint16_t request, P... pairs) {
        if (config.access_log.empty()) return;
        std::string s_pairs[]{log_pair_to_str(pairs)...};
        access_log << session->login << "\tREQ " << request_name(request);
        for (auto &s_p : s_pairs) access_log << " " << s_p;
        access_log << std::endl;
    }

    template<typename... P>
    void log_error(Session *session, uint16_t status, P... pairs) {
        if (config.access_log.empty()) return;
        std::string s_pairs[]{log_pair_to_str(pairs)...};
        access_log << session->login << "\tERR '" << request_status_string(status) << "'";
        for (auto &s_p : s_pairs) access_log << " " << s_p;
        access_log << std::endl;
    }

    template<typename... P>
    void log_response(Session *session, P... pairs) {
        if (config.access_log.empty()) return;
        std::string s_pairs[]{log_pair_to_str(pairs)...};
        access_log << session->login << "\tANS";
        for (auto &s_p : s_pairs) access_log << " " << s_p;
        access_log << std::endl;
    }

public:
    CloudServer(NetServer *net, const CloudConfig &config);

    void wait_destroy();

    ~CloudServer();
};

#endif //CLOUD9_CLOUD_SERVER_H
