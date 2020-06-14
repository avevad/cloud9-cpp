#ifndef CLOUD9_CLOUD_CLIENT_H
#define CLOUD9_CLOUD_CLIENT_H

#include <string>
#include <mutex>
#include <functional>
#include "networking.h"
#include "cloud_common.h"


class CloudClient final {
private:
    NetConnection *const connection;
    std::mutex lock;
public:
    CloudClient(NetConnection *net, const std::string &login, std::string (*password_callback)(void *), void *ud);

    ~CloudClient();

    Node get_home(const std::string &user);

    Node get_home();

    void list_directory(Node node, const std::function<void(std::string, Node)> &callback);

    void get_parent(Node node, Node *parent, bool *has_parent);
};

#endif //CLOUD9_CLOUD_CLIENT_H
