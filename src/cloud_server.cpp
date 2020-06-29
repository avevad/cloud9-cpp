#include <cstring>
#include <iostream>
#include <filesystem>
#include <fstream>
#include "cloud_server.h"
#include "cloud_common.h"

CloudConfig::CloudConfig() = default;

CloudConfig::~CloudConfig() = default;

CloudServer::CloudServer(NetServer *net, const CloudConfig &config) : config(config), net(net),
                                                                      connector(new std::thread(
                                                                              [this] { connector_routine(); })) {

}

CloudServer::~CloudServer() {
    shutting_down = true;
    net->destroy();
    if (connector->joinable()) connector->join();
    delete connector;
    delete net;
    for (Session *session : sessions) {
        session->connection->close();
    }
    for (std::thread *listener : listeners) {
        if (listener->joinable()) listener->join();
        delete listener;
    }
}

void CloudServer::connector_routine() {
    while (true) {
        try {
            NetConnection *connection = net->accept();
            auto *session = new Session(connection);
            sessions.insert(session);
            auto *listener = new std::thread(&CloudServer::listener_routine, this, session);
            listeners.push_back(listener);
        } catch (std::runtime_error &error) {
            if (!shutting_down) std::cerr << "connector exited with exception: " << error.what() << std::endl;
            break;
        }
    }
}

void CloudServer::listener_routine(Session *session) {
    char *body = nullptr;
    try {
#define INIT_ERR(err) {send_uint16(session->connection, err); throw std::runtime_error(init_status_string(err));}
        auto cmd = read_uint16(session->connection);
        auto size = read_uint64(session->connection);
        if (size > INIT_BODY_MAX_SIZE) INIT_ERR(INIT_ERR_BODY_TOO_LARGE);
        body = new char[size];
        read_exact(session->connection, size, body);
        if (cmd == INIT_CMD_AUTH) {
            if (size == 0) INIT_ERR(INIT_ERR_MALFORMED_CMD);
            uint8_t login_length = *reinterpret_cast<uint8_t *>(body);
            if (login_length > size - sizeof(uint8_t)) INIT_ERR(INIT_ERR_MALFORMED_CMD);
            session->login = std::string(body + sizeof(uint8_t), login_length);
            std::string password(body + sizeof(uint8_t) + login_length, body + size);
            if (!is_valid_login(session->login)) INIT_ERR(INIT_ERR_AUTH_FAILED);
            std::string user_file_path = config.users_directory + PATH_DIV + session->login;
            if (!std::filesystem::is_regular_file(user_file_path)) INIT_ERR(INIT_ERR_AUTH_FAILED);
            std::ifstream user_file(user_file_path);
            std::string user_string((std::istreambuf_iterator<char>(user_file)), std::istreambuf_iterator<char>());
            std::string salt = user_string.substr(0, USER_PASSWORD_SALT_LENGTH);
            std::string password_salted = password + salt;
            char *sha256 = new char[SHA256_DIGEST_LENGTH + 1];
            SHA256(reinterpret_cast<const unsigned char *>(password_salted.c_str()), password_salted.length(),
                   reinterpret_cast<unsigned char *>(sha256));
            sha256[SHA256_DIGEST_LENGTH] = '\0';
            std::string sha256_real = user_string.substr(USER_PASSWORD_SALT_LENGTH, SHA256_DIGEST_LENGTH);
            bool ok = strcmp(sha256, sha256_real.c_str()) == 0;
            delete[] sha256;
            if (ok) send_uint16(session->connection, INIT_OK);
            else INIT_ERR(INIT_ERR_AUTH_FAILED);
        } else INIT_ERR(INIT_ERR_INVALID_CMD);
#undef INIT_ERR
    } catch (std::exception &exception) {
        if (!shutting_down) std::cerr << "failed to initialize client connection: " << exception.what() << std::endl;
        delete[] body;
        session->connection->close();
        delete session->connection;
        sessions.erase(session);
        delete session;
        return;
    }
    bool goodbye = false;
    try {
        while (true) {
            auto cmd = read_uint16(session->connection);
            auto size = read_uint64(session->connection);
            if (size > REQUEST_BODY_MAX_SIZE) {
                send_uint16(session->connection, REQUEST_ERR_BODY_TOO_LARGE);
                send_uint64(session->connection, 0);
                throw std::runtime_error(request_status_string(REQUEST_ERR_BODY_TOO_LARGE));
            }
            delete[] body;
            body = new char[size];
            read_exact(session->connection, size, body);
            if (cmd == REQUEST_CMD_GET_HOME) {
                std::string user = size == 0 ? session->login : std::string(body, size);
                std::string user_file_path = config.users_directory + PATH_DIV + user;
                if (!std::filesystem::is_regular_file(user_file_path)) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                } else {
                    std::ifstream user_file(user_file_path);
                    std::string user_string((std::istreambuf_iterator<char>(user_file)),
                                            std::istreambuf_iterator<char>());
                    const Node *node = reinterpret_cast<const Node *>(user_string.c_str() + USER_PASSWORD_SALT_LENGTH +
                                                                      SHA256_DIGEST_LENGTH);
                    send_uint16(session->connection, REQUEST_OK);
                    send_uint64(session->connection, sizeof(Node));
                    send_exact(session->connection, sizeof(Node), node);
                }
            } else if (cmd == REQUEST_CMD_LIST_DIRECTORY) {
                if (size != sizeof(Node)) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                auto[node_head, head_size] = get_node_head(node);
                if (!node_head) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                int type = *(node_head + NODE_HEAD_OFFSET_TYPE);
                delete[] node_head;
                ReadWrite rights = get_user_rights(node, session->login);
                if (!rights.read) {
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (type != NODE_TYPE_DIRECTORY) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::ifstream node_data_file(get_node_data_path(node));
                std::string node_data((std::istreambuf_iterator<char>(node_data_file)),
                                      std::istreambuf_iterator<char>());
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, node_data.size());
                send_exact(session->connection, node_data.size(), node_data.c_str());
            } else if (cmd == REQUEST_CMD_GOODBYE) {
                goodbye = true;
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, size);
                send_exact(session->connection, size, body);
            } else if (cmd == REQUEST_CMD_GET_PARENT) {
                if (size != sizeof(Node)) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                uint16_t error = REQUEST_OK;
                Node parent;
                bool ok = get_parent(node, parent, error);
                if (error != REQUEST_ERR_NOT_FOUND) {
                    ReadWrite rights = get_user_rights(node, session->login);
                    if (!rights.read) {
                        send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                        send_uint64(session->connection, 0);
                        continue;
                    }
                }
                if (ok) {
                    send_uint16(session->connection, REQUEST_OK);
                    send_uint64(session->connection, sizeof(Node));
                    send_exact(session->connection, sizeof(Node), &parent);
                } else {
                    send_uint16(session->connection, error);
                    send_uint64(session->connection, 0);
                }
            } else if (cmd == REQUEST_CMD_MAKE_NODE) {
                if (size < sizeof(Node) + 1) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto name_len = *reinterpret_cast<uint8_t *>(body + sizeof(Node));
                if (sizeof(Node) + 1 + name_len + 1 != size) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::string name(body + sizeof(Node) + 1, name_len);
                if (!is_valid_name(name)) {
                    send_uint16(session->connection, REQUEST_ERR_INVALID_NAME);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t type = body[size - 1];
                if (type != NODE_TYPE_FILE && type != NODE_TYPE_DIRECTORY) {
                    send_uint16(session->connection, REQUEST_ERR_INVALID_TYPE);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node parent = *reinterpret_cast<Node *>(body);
                if (!get_user_rights(parent, session->login).write) {
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[parent_head, parent_head_size] = get_node_head(parent);
                if (!parent_head) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (*reinterpret_cast<uint8_t *>(parent_head + NODE_HEAD_OFFSET_TYPE) != NODE_TYPE_DIRECTORY) {
                    delete[] parent_head;
                    send_uint16(session->connection, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[parent_data, parent_data_size] = get_node_data(parent);
                std::string parent_data_string(parent_data, parent_data_size);
                delete[] parent_data;
                Node node = generate_node();
                parent_data_string += std::string(reinterpret_cast<const char *>(&node), sizeof(Node));
                parent_data_string += ' ';
                parent_data_string.back() = name_len;
                parent_data_string += name;
                {
                    std::ofstream parent_data_file(get_node_data_path(parent));
                    parent_data_file << parent_data_string;
                }
                {
                    std::ofstream data_stream(get_node_data_path(node));
                    std::ofstream head_stream(get_node_head_path(node));
                    std::string header;
                    header += type;
                    header += parent_head[NODE_HEAD_OFFSET_RIGHTS];
                    header += name_len;
                    header += name;
                    header += std::string(reinterpret_cast<const char *>(&parent), sizeof(Node));
                    head_stream << header;
                }
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else {
                send_uint16(session->connection, REQUEST_ERR_INVALID_CMD);
                send_uint64(session->connection, 0);
            }
        }
    } catch (std::exception &exception) {
        if (!shutting_down && !goodbye)
            std::cerr << "'" << session->login << "' listener stopped with exception: " << exception.what()
                      << std::endl;
    }
    delete[] body;
    session->connection->close();
    delete session->connection;
    sessions.erase(session);
    delete session;
}

void CloudServer::wait_destroy() {
    if (connector->joinable()) connector->join();
}

std::pair<char *, size_t> CloudServer::get_node_head(Node node) {
    std::string node_file_path = get_node_head_path(node);
    if (!std::filesystem::is_regular_file(node_file_path)) return {nullptr, 0};
    std::ifstream node_file(node_file_path);
    std::string node_string((std::istreambuf_iterator<char>(node_file)), std::istreambuf_iterator<char>());
    char *node_head = new char[node_string.size() + 1];
    memcpy(node_head, node_string.c_str(), node_string.length());
    return {node_head, node_string.length()};
}

std::pair<char *, size_t> CloudServer::get_node_data(Node node) {
    std::string node_file_path = get_node_data_path(node);
    if (!std::filesystem::is_regular_file(node_file_path)) return {nullptr, 0};
    std::ifstream node_file(node_file_path);
    std::string node_string((std::istreambuf_iterator<char>(node_file)), std::istreambuf_iterator<char>());
    char *node_data = new char[node_string.size() + 1];
    memcpy(node_data, node_string.c_str(), node_string.length());
    return {node_data, node_string.length()};
}

std::string CloudServer::get_node_data_path(Node node) {
    return config.nodes_data_directory + PATH_DIV + node2string(node);
}

ReadWrite CloudServer::get_user_rights(Node node, const std::string &user) {
    ReadWrite user_rights;
    auto[node_head, head_size] = get_node_head(node);
    uint8_t rights = *reinterpret_cast<const uint8_t *>(node_head + NODE_HEAD_OFFSET_RIGHTS);
    Node home = node;
    uint16_t error;
    while (get_parent(home, home, error));
    std::string owner;
    get_home_owner(home, error, owner);
    if (owner == user) user_rights.read = user_rights.write = true;
    //TODO: add group rights
    if (rights & NODE_RIGHTS_ALL_READ) user_rights.read = true;
    if (rights & NODE_RIGHTS_ALL_WRITE) user_rights.write = true;
    return user_rights;
}

bool CloudServer::get_parent(Node node, Node &parent, uint16_t &error) {
    auto[node_head, node_size] = get_node_head(node);
    if (!node_head) {
        error = REQUEST_ERR_NOT_FOUND;
        return false;
    }
    auto owner_size = (size_t) *reinterpret_cast<unsigned char *>(node_head + NODE_HEAD_OFFSET_OWNER_GROUP_SIZE);
    Node *parent_ptr = reinterpret_cast<Node *>(node_head + NODE_HEAD_OFFSET_OWNER_GROUP + owner_size);
    Node result;
    bool ok;
    if (parent_ptr >= reinterpret_cast<Node *>(node_head + node_size)) {
        ok = false;
    } else {
        result = *parent_ptr;
        ok = true;
    }
    if (ok) parent = *parent_ptr;
    delete node_head;
    return ok;
}

bool CloudServer::get_home_owner(Node node, uint16_t &error, std::string &owner) {
    bool found = false;
    for (const auto &entry : std::filesystem::directory_iterator(config.users_directory)) {
        std::ifstream user_file(entry.path());
        std::string user_string((std::istreambuf_iterator<char>(user_file)),
                                std::istreambuf_iterator<char>());
        const Node *home = reinterpret_cast<const Node *>(user_string.c_str() + USER_PASSWORD_SALT_LENGTH +
                                                          SHA256_DIGEST_LENGTH);
        if (*home == node) {
            found = true;
            owner = entry.path().filename();
            break;
        }
    }
    return found;
}

Node CloudServer::generate_node() {
    Node node;
    size_t iter = 0;
    while (iter++ == 0 || std::filesystem::is_regular_file(get_node_data_path(node))) {
        for (unsigned char &b : node.id) {
            b = std::rand() % 0xFF;
        }
    }
    return node;
}

std::string CloudServer::get_node_head_path(Node node) {
    return config.nodes_head_directory + PATH_DIV + node2string(node);
}

CloudServer::Session::Session(NetConnection *connection) : connection(connection) {

}
