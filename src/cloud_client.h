#ifndef CLOUD9_CLOUD_CLIENT_H
#define CLOUD9_CLOUD_CLIENT_H

#include <string>
#include <mutex>
#include <functional>
#include <thread>
#include <condition_variable>
#include <map>
#include "networking.h"
#include "cloud_common.h"

typedef struct {
    uint8_t type;
    uint64_t size;
    uint8_t rights;
} NodeInfo;

class CloudClient final {
private:
    struct ServerResponse {
        uint16_t status = 0;
        uint64_t size = 0;
        char *body = nullptr;
    };
    NetConnection *const connection;
    std::mutex api_lock;
    std::mutex ldtm_lock;
    std::thread listener;
    std::condition_variable response_notifier;
    std::map<uint32_t, ServerResponse> responses;
    uint32_t current_id = 0;
    bool connected = true;
public:
    CloudClient(NetConnection *net, const std::string &login, const std::function<std::string()> &password_callback);

    CloudClient(NetConnection *net, const std::string &login, const std::function<std::string()> &invite_callback,
                const std::function<std::string()> &password_callback);

    ~CloudClient();

    Node get_home(const std::string &user = "");

    void list_directory(Node node, const std::function<void(std::string, Node)> &callback);

    bool get_parent(Node node, Node *parent);

    Node make_node(Node parent, const std::string &name, uint8_t type);

    std::string get_node_owner(Node node);

    uint8_t fd_open(Node node, uint8_t mode);

    void fd_close(uint8_t fd);

    uint32_t fd_read(uint8_t fd, uint32_t n, void *bytes);

    void fd_write(uint8_t fd, uint32_t n, const void *bytes);

    void fd_read_long(uint8_t fd, uint64_t count, char *buffer, uint32_t buf_size,
                      const std::function<void(uint32_t)> &callback);

    void fd_write_long(uint8_t fd, uint64_t count, const char *buffer, const std::function<uint32_t()> &callback);

    NodeInfo get_node_info(Node node);

    void set_node_rights(Node node, uint8_t rights);

    void listener_routine();

    void group_invite(const std::string &user);

    void group_kick(const std::string &user);

    void group_list(const std::function<void(std::string)> &callback);

    void remove_node(Node node);

    std::string get_node_group(Node node);

    void set_node_group(Node node, const std::string &group);

    void move_node(Node node, Node new_parent);

    Node copy_node(Node node, const std::string &name);

    void rename_node(Node node, const std::string &name);

    ServerResponse wait_response(uint32_t id, std::unique_lock<std::mutex> &locker);
};

class CloudInitError : public std::exception {
public:
    const uint16_t status;
    const std::string desc;

    explicit CloudInitError(uint16_t status);

public:
    [[nodiscard]] const char *what() const noexcept override;
};

class CloudRequestError : public std::exception {
public:
    const uint16_t status;
    const std::string info;
    const std::string desc;

    explicit CloudRequestError(uint16_t status, std::string info = "");

public:
    [[nodiscard]] const char *what() const noexcept override;
};

#endif //CLOUD9_CLOUD_CLIENT_H
