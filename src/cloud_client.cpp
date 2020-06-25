#include <stdexcept>
#include <functional>
#include "cloud_client.h"
#include "cloud_common.h"

CloudClient::CloudClient(NetConnection *net, const std::string &login, std::string (*password_callback)(void *),
                         void *ud) : connection(net) {
    send_uint16(net, INIT_CMD_AUTH);
    std::string password = password_callback(ud);
    size_t size = sizeof(uint8_t) + login.size() + password.size();
    send_uint64(net, size);
    send_uint8(net, login.size());
    send_exact(net, login.size(), login.c_str());
    send_exact(net, password.size(), password.c_str());
    uint16_t status = read_uint16(net);
    if (status != INIT_OK) {
        throw CloudInitError(status);
    }
}

CloudClient::~CloudClient() {
    try {
        std::unique_lock<std::mutex> locker(lock);
        send_uint16(connection, REQUEST_CMD_GOODBYE);
        send_uint64(connection, 0);
    } catch (std::exception &exception) {}
}

Node CloudClient::get_home(const std::string &user) {
    std::unique_lock<std::mutex> locker(lock);
    send_uint16(connection, REQUEST_CMD_GET_HOME);
    send_uint64(connection, user.size());
    send_exact(connection, user.size(), user.c_str());
    auto status = read_uint16(connection);
    auto size = read_uint64(connection);
    auto *buffer = new unsigned char[size];
    read_exact(connection, size, buffer);
    if (status != REQUEST_OK) {
        delete[] buffer;
        throw CloudRequestError(status);
    }
    if (size != sizeof(Node)) {
        delete[] buffer;
        throw std::runtime_error("server error");
    }
    Node node = *reinterpret_cast<Node *>(buffer);
    delete[] buffer;
    return node;
}

Node CloudClient::get_home() {
    return get_home("");
}

void CloudClient::list_directory(Node node, const std::function<void(std::string, Node)> &callback) {
    std::unique_lock<std::mutex> locker(lock);
    send_uint16(connection, REQUEST_CMD_LIST_DIRECTORY);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    auto status = read_uint16(connection);
    auto size = read_uint64(connection);
    auto *buffer = new unsigned char[size];
    read_exact(connection, size, buffer);
    if (status != REQUEST_OK) {
        delete[] buffer;
        throw CloudRequestError(status);
    }
    size_t offset = 0;
    while (offset < size) {
        Node child = *reinterpret_cast<Node *>(buffer + offset);
        offset += sizeof(Node);
        auto length = (size_t) * reinterpret_cast<unsigned char *>(buffer + offset);
        offset += 1;
        std::string name(reinterpret_cast<const char *>(buffer + offset), length);
        offset += length;
        callback(name, child);
    }
    delete[] buffer;
}

void CloudClient::get_parent(Node node, Node *parent, bool *has_parent) {
    std::unique_lock<std::mutex> locker(lock);
    send_uint16(connection, REQUEST_CMD_GET_PARENT);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    auto status = read_uint16(connection);
    auto size = read_uint64(connection);
    auto *buffer = new unsigned char[size];
    read_exact(connection, size, buffer);
    if (status != REQUEST_OK) {
        delete[] buffer;
        throw CloudRequestError(status);
    }
    bool result = size == sizeof(Node);
    if (has_parent) *has_parent = result;
    if (result && parent) *parent = *reinterpret_cast<Node *>(buffer);
    delete[] buffer;
}

CloudRequestError::CloudRequestError(uint16_t status, std::string info) : desc(
        info.empty() ? request_status_string(status) : (request_status_string(status) + " (" + info + ")")),
                                                                          status(status), info(std::move(info)) {

}

const char *CloudRequestError::what() const noexcept {
    return desc.c_str();
}

CloudInitError::CloudInitError(uint16_t status) : status(status), desc(init_status_string(status)) {

}

const char *CloudInitError::what() const noexcept {
    return desc.c_str();
}
