#include <stdexcept>
#include <functional>
#include "cloud_client.h"
#include "cloud_common.h"

CloudClient::CloudClient(NetConnection *net, const std::string &login, std::string (*password_callback)(void *),
                         void *ud) : connection(net) {
    send_any(net, INIT_CMD_AUTH);
    std::string password = password_callback(ud);
    size_t size = sizeof(size_t) + login.size() + password.size();
    send_any(net, size);
    send_any(net, login.size());
    send_exact(net, login.size(), login.c_str());
    send_exact(net, password.size(), password.c_str());
    int status = read_any<int>(net);
    if (status != INIT_OK) {
        throw std::runtime_error(init_status_string(status));
    }
}

CloudClient::~CloudClient() {
    try {
        std::unique_lock<std::mutex> locker(lock);
        send_any(connection, REQUEST_CMD_GOODBYE);
        send_any<size_t>(connection, 0);
    } catch (std::exception &exception) {}
}

Node CloudClient::get_home(const std::string &user) {
    std::unique_lock<std::mutex> locker(lock);
    send_any(connection, REQUEST_CMD_GET_HOME);
    send_any(connection, user.size());
    send_exact(connection, user.size(), user.c_str());
    auto status = read_any<int>(connection);
    auto size = read_any<size_t>(connection);
    auto *buffer = new unsigned char[size];
    read_exact(connection, size, buffer);
    if (status != REQUEST_OK) {
        delete[] buffer;
        throw std::runtime_error(request_status_string(status));
    }
    if (size != sizeof(Node)) {
        delete[] buffer;
        throw std::runtime_error("server error");
    }
    Node node = *(Node *) buffer;
    delete[] buffer;
    return node;
}

void CloudClient::list_directory(Node node, const std::function<void(std::string, Node)> &callback) {
    std::unique_lock<std::mutex> locker(lock);
    send_any(connection, REQUEST_CMD_LIST_DIRECTORY);
    send_any(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    auto status = read_any<int>(connection);
    auto size = read_any<size_t>(connection);
    auto *buffer = new unsigned char[size];
    read_exact(connection, size, buffer);
    if (status != REQUEST_OK) {
        delete[] buffer;
        throw std::runtime_error(request_status_string(status));
    }
    size_t offset = 0;
    while (offset < size) {
        Node child = *(Node *) (buffer + offset);
        offset += sizeof(Node);
        auto length = (size_t) *(unsigned char *) (buffer + offset);
        offset += 1;
        std::string name((const char *) (buffer + offset), length);
        offset += length;
        callback(name, child);
    }
    delete[] buffer;
}
