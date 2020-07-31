#include <stdexcept>
#include <functional>
#include "cloud_client.h"
#include "cloud_common.h"
#include <unistd.h>

CloudClient::CloudClient(NetConnection *net, const std::string &login,
                         const std::function<std::string()> &password_callback)
        : connection(net) {
    negotiate(net);
    send_uint16(net, INIT_CMD_AUTH);
    std::string password = password_callback();
    size_t size = sizeof(uint8_t) + login.size() + password.size();
    send_uint64(net, size);
    send_uint8(net, login.size());
    send_exact(net, login.size(), login.c_str());
    send_exact(net, password.size(), password.c_str());
    net->flush();
    uint16_t status = read_uint16(net);
    if (status != INIT_OK) {
        throw CloudInitError(status);
    }
    listener = std::thread([this]() { listener_routine(); });
}

CloudClient::CloudClient(NetConnection *net, const std::string &login,
                         const std::function<std::string()> &invite_callback,
                         const std::function<std::string()> &password_callback) : connection(net) {
    negotiate(net);
    send_uint16(net, INIT_CMD_REGISTER);
    std::string invite = invite_callback();
    std::string password = password_callback();
    size_t size = 1 + invite.length() + 1 + login.length() + password.length();
    send_uint64(net, size);
    send_uint8(net, invite.length());
    send_exact(net, invite.length(), invite.c_str());
    send_uint8(net, login.length());
    send_exact(net, login.length(), login.c_str());
    send_exact(net, password.length(), password.c_str());
    net->flush();
    uint16_t status = read_uint16(net);
    if (status != INIT_OK) {
        throw CloudInitError(status);
    }
    listener = std::thread([this]() { listener_routine(); });
}

CloudClient::~CloudClient() {
    if (connected) {
        try {
            std::unique_lock<std::mutex> locker(api_lock);
            send_uint32(connection, current_id);
            send_uint16(connection, REQUEST_CMD_GOODBYE);
            send_uint64(connection, 0);
            connection->flush();
            if (listener.joinable()) listener.detach();
        } catch (std::exception &exception) {}
    } else {
        if (listener.joinable()) listener.join();
    }
}


void CloudClient::listener_routine() {
    ServerResponse response;
    try {
        while (!terminate_listener) {
            response = ServerResponse();
            uint32_t id = read_uint32(connection);
            response.status = read_uint16(connection);
            response.size = read_uint64(connection);
            response.body = new char[response.size];
            read_exact(connection, response.size, response.body);
            responses[id] = response;
            response_notifier.notify_all();
            if (response.status == REQUEST_SWITCH_OK) {
                std::unique_lock locker(ldtm_lock);
            }
        }
    } catch (std::runtime_error &error) {
        connected = false;
        response_notifier.notify_all();
        delete[] response.body;
    }
}

CloudClient::ServerResponse CloudClient::wait_response(uint32_t id, std::unique_lock<std::mutex> &locker) {
    connection->flush();
    while (connected && responses.find(id) == responses.end()) response_notifier.wait(locker);
    if (!connected) throw std::runtime_error("not connected");
    ServerResponse response = responses[id];
    responses.erase(id);
    return response;
}

Node CloudClient::get_home(const std::string &user) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GET_HOME);
    send_uint64(connection, user.size());
    send_exact(connection, user.size(), user.c_str());
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    Node node = *reinterpret_cast<Node *>(response.body);
    delete[] response.body;
    return node;
}

void CloudClient::list_directory(Node node, const std::function<void(std::string, Node)> &callback) {
    std::vector<std::pair<std::string, Node>> children;
    {
        std::unique_lock<std::mutex> locker(api_lock);
        send_uint32(connection, current_id);
        send_uint16(connection, REQUEST_CMD_LIST_DIRECTORY);
        send_uint64(connection, sizeof(Node));
        send_exact(connection, sizeof(Node), &node);
        ServerResponse response = wait_response(current_id++, locker);
        if (response.status != REQUEST_OK) {
            delete[] response.body;
            throw CloudRequestError(response.status);
        }
        size_t offset = 0;
        while (offset < response.size) {
            Node child = *reinterpret_cast<Node *>(response.body + offset);
            offset += sizeof(Node);
            auto length = (size_t) *reinterpret_cast<unsigned char *>(response.body + offset);
            offset += 1;
            std::string name(reinterpret_cast<const char *>(response.body + offset), length);
            offset += length;
            children.emplace_back(name, child);
        }
        delete[] response.body;
    }
    for (auto[name, child] : children) callback(name, child);
}

bool CloudClient::get_parent(Node node, Node *parent) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GET_PARENT);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    bool result = response.size == sizeof(Node);
    if (result && parent) *parent = *reinterpret_cast<Node *>(response.body);
    delete[] response.body;
    return result;
}

Node CloudClient::make_node(Node parent, const std::string &name, uint8_t type) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_MAKE_NODE);
    send_uint64(connection, sizeof(Node) + 1 + name.length() + 1);
    send_exact(connection, sizeof(Node), &parent);
    send_uint8(connection, name.length());
    send_exact(connection, name.length(), name.c_str());
    send_uint8(connection, type);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    Node node = *reinterpret_cast<Node *>(response.body);
    delete[] response.body;
    return node;
}

std::string CloudClient::get_node_owner(Node node) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GET_NODE_OWNER);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    std::string owner(response.body, response.size);
    delete[] response.body;
    return owner;
}

uint8_t CloudClient::fd_open(Node node, uint8_t mode) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_FD_OPEN);
    send_uint64(connection, sizeof(Node) + 1);
    send_exact(connection, sizeof(Node), &node);
    send_uint8(connection, mode);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    uint8_t fd = *reinterpret_cast<uint8_t *>(response.body);
    delete[] response.body;
    return fd;
}

void CloudClient::fd_close(uint8_t fd) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_FD_CLOSE);
    send_uint64(connection, 1);
    send_uint8(connection, fd);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    delete[] response.body;
}

void CloudClient::fd_write(uint8_t fd, uint32_t n, const void *bytes) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_FD_WRITE);
    send_uint64(connection, 1 + n);
    send_uint8(connection, fd);
    send_exact(connection, n, bytes);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    delete[] response.body;
}

uint32_t CloudClient::fd_read(uint8_t fd, uint32_t n, void *bytes) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_FD_READ);
    send_uint64(connection, 1 + sizeof(uint32_t));
    send_uint8(connection, fd);
    send_uint32(connection, n);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    std::memcpy(bytes, response.body, response.size);
    delete[] response.body;
    return response.size;
}

NodeInfo CloudClient::get_node_info(Node node) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GET_NODE_INFO);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    NodeInfo node_info;
    char *p = response.body;
    node_info.type = *reinterpret_cast<uint8_t *>(p);
    p += sizeof(uint8_t);
    node_info.size = buf_read_uint64(p);
    p += sizeof(uint64_t);
    node_info.rights = *reinterpret_cast<uint8_t *>(p);
    delete[] response.body;
    return node_info;
}


void CloudClient::fd_read_long(uint8_t fd, uint64_t count, char *buffer, uint32_t buf_size,
                               const std::function<void(uint32_t)> &callback) {
    std::unique_lock<std::mutex> locker(api_lock);
    std::unique_lock<std::mutex> locker_ldtm(ldtm_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_FD_READ_LONG);
    send_uint64(connection, 1 + sizeof(uint64_t));
    send_uint8(connection, fd);
    send_uint64(connection, count);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_SWITCH_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    delete[] response.body;
    uint64_t done = 0;
    while (done < count) {
        uint32_t read = connection->read(std::min(uint64_t(buf_size), count - done), buffer);
        callback(read);
        done += uint64_t(read);
    }
}

void CloudClient::fd_write_long(uint8_t fd, uint64_t count, const char *buffer,
                                const std::function<uint32_t()> &callback) {
    std::unique_lock<std::mutex> locker(api_lock);
    std::unique_lock<std::mutex> locker_ldtm(ldtm_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_FD_WRITE_LONG);
    send_uint64(connection, 1 + sizeof(uint64_t));
    send_uint8(connection, fd);
    send_uint64(connection, count);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_SWITCH_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    delete[] response.body;
    uint64_t done = 0;
    while (done < count) {
        uint32_t sent = callback();
        send_exact(connection, sent, buffer);
        done += uint64_t(sent);
    }
}

void CloudClient::set_node_rights(Node node, uint8_t rights) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_SET_NODE_RIGHTS);
    send_uint64(connection, sizeof(Node) + 1);
    send_exact(connection, sizeof(Node), &node);
    send_uint8(connection, rights);
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

void CloudClient::group_invite(const std::string &user) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GROUP_INVITE);
    send_uint64(connection, user.length());
    send_exact(connection, user.length(), user.c_str());
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

std::string CloudClient::get_node_group(Node node) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GET_NODE_GROUP);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    std::string group(response.body, response.size);
    return group;
}

void CloudClient::remove_node(Node node) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_REMOVE_NODE);
    send_uint64(connection, sizeof(Node));
    send_exact(connection, sizeof(Node), &node);
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

void CloudClient::set_node_group(Node node, const std::string &group) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_SET_NODE_GROUP);
    send_uint64(connection, sizeof(Node) + group.length());
    send_exact(connection, sizeof(Node), &node);
    send_exact(connection, group.length(), group.c_str());
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

void CloudClient::group_kick(const std::string &user) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_GROUP_KICK);
    send_uint64(connection, user.length());
    send_exact(connection, user.length(), user.c_str());
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

void CloudClient::group_list(const std::function<void(std::string)> &callback) {
    std::string groups;
    {
        std::unique_lock<std::mutex> locker(api_lock);
        send_uint32(connection, current_id);
        send_uint16(connection, REQUEST_CMD_GROUP_LIST);
        send_uint64(connection, 0);
        ServerResponse response = wait_response(current_id++, locker);
        if (response.status != REQUEST_OK) {
            delete[] response.body;
            throw CloudRequestError(response.status);
        }
        groups = std::string(response.body, response.size);
        delete[] response.body;
    }
    size_t pos = 0;
    while (pos < groups.size()) {
        uint8_t length = groups[pos];
        pos++;
        std::string group = groups.substr(pos, length);
        callback(group);
        pos += length;
    }
}

void CloudClient::move_node(Node node, Node new_parent) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_MOVE_NODE);
    send_uint64(connection, sizeof(Node) * 2);
    send_exact(connection, sizeof(Node), &node);
    send_exact(connection, sizeof(Node), &new_parent);
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

Node CloudClient::copy_node(Node node, const std::string &name) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_COPY_NODE);
    send_uint64(connection, sizeof(Node) + name.length());
    send_exact(connection, sizeof(Node), &node);
    send_exact(connection, name.length(), name.c_str());
    ServerResponse response = wait_response(current_id++, locker);
    if (response.status != REQUEST_OK) {
        delete[] response.body;
        throw CloudRequestError(response.status);
    }
    Node clone = *reinterpret_cast<Node *>(response.body);
    delete[] response.body;
    return clone;
}

void CloudClient::rename_node(Node node, const std::string &name) {
    std::unique_lock<std::mutex> locker(api_lock);
    send_uint32(connection, current_id);
    send_uint16(connection, REQUEST_CMD_RENAME_NODE);
    send_uint64(connection, sizeof(Node) + name.length());
    send_exact(connection, sizeof(Node), &node);
    send_exact(connection, name.length(), name.c_str());
    ServerResponse response = wait_response(current_id++, locker);
    delete[] response.body;
    if (response.status != REQUEST_OK) {
        throw CloudRequestError(response.status);
    }
}

void CloudClient::negotiate(NetConnection *net) {
    char client_header[CLOUD9_FULL_HEADER_LENGTH];
    memcpy(&client_header, CLOUD9_HEADER, CLOUD9_HEADER_LENGTH);
    buf_send_uint16(client_header + CLOUD9_HEADER_LENGTH, CLOUD9_REL_CODE);
    send_exact(net, CLOUD9_FULL_HEADER_LENGTH, &client_header);
    net->flush();
    char server_header[CLOUD9_FULL_HEADER_LENGTH];
    read_exact(net, CLOUD9_FULL_HEADER_LENGTH, &server_header);
    if (memcmp(&server_header, &client_header, CLOUD9_HEADER_LENGTH) != 0)
        throw std::runtime_error("negotiation error: invalid header");
    if (memcmp(&server_header, &client_header, CLOUD9_FULL_HEADER_LENGTH) != 0)
        throw std::runtime_error("negotiation error: version mismatch");
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
