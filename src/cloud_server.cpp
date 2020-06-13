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
#define INIT_ERR(err) {send_any(session->connection, err); throw std::runtime_error(init_status_string(err));}
        auto cmd = read_any<int>(session->connection);
        auto size = read_any<size_t>(session->connection);
        if (size > INIT_BODY_MAX_SIZE) INIT_ERR(INIT_ERR_BODY_TOO_LARGE);
        body = new char[size];
        read_exact(session->connection, size, body);
        if (cmd == INIT_CMD_AUTH) {
            if (size == 0) INIT_ERR(INIT_ERR_MALFORMED_CMD);
            size_t login_length = *(size_t *) body;
            if (login_length > size - sizeof(size_t)) INIT_ERR(INIT_ERR_MALFORMED_CMD);
            session->login = std::string(body + sizeof(size_t), login_length);
            std::string password(body + sizeof(size_t) + login_length, body + size);
            if (!is_valid_login(session->login)) INIT_ERR(INIT_ERR_AUTH_FAILED);
            std::string user_file_path = config.users_directory + PATH_DIV + session->login;
            if (!std::filesystem::is_regular_file(user_file_path)) INIT_ERR(INIT_ERR_AUTH_FAILED);
            std::ifstream user_file(user_file_path);
            std::string user_string((std::istreambuf_iterator<char>(user_file)), std::istreambuf_iterator<char>());
            std::string salt = user_string.substr(0, USER_PASSWORD_SALT_LENGTH);
            std::string password_salted = password + salt;
            char *sha256 = new char[SHA256_DIGEST_LENGTH + 1];
            SHA256((unsigned char *) password_salted.c_str(), password_salted.length(), (unsigned char *) sha256);
            sha256[SHA256_DIGEST_LENGTH] = '\0';
            std::string sha256_real = user_string.substr(USER_PASSWORD_SALT_LENGTH, SHA256_DIGEST_LENGTH);
            bool ok = strcmp(sha256, sha256_real.c_str()) == 0;
            delete[] sha256;
            if (ok) send_any(session->connection, INIT_OK);
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
            auto cmd = read_any<int>(session->connection);
            auto size = read_any<size_t>(session->connection);
            if (size > REQUEST_BODY_MAX_SIZE) {
                send_any(session->connection, REQUEST_ERR_BODY_TOO_LARGE);
                send_any<size_t>(session->connection, 0);
                throw std::runtime_error(request_status_string(REQUEST_ERR_BODY_TOO_LARGE));
            }
            delete[] body;
            body = new char[size];
            read_exact(session->connection, size, body);
            if (cmd == REQUEST_CMD_GET_HOME) {
                std::string user(body, size);
                std::string user_file_path = config.users_directory + PATH_DIV + user;
                if (!std::filesystem::is_regular_file(user_file_path)) {
                    send_any(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_any<size_t>(session->connection, 0);
                } else {
                    std::ifstream user_file(user_file_path);
                    std::string user_string((std::istreambuf_iterator<char>(user_file)),
                                            std::istreambuf_iterator<char>());
                    Node *node = (Node *) (user_string.c_str() + USER_PASSWORD_SALT_LENGTH + SHA256_DIGEST_LENGTH);
                    send_any(session->connection, REQUEST_OK);
                    send_any(session->connection, sizeof(Node));
                    send_any(session->connection, *node);
                }
            } else if (cmd == REQUEST_CMD_LIST_DIRECTORY) {
                if (size != sizeof(Node)) {
                    send_any(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_any<size_t>(session->connection, 0);
                    continue;
                }
                Node node = *(Node *) body;
                char *node_head = get_node_head(node);
                if (!node_head) {
                    send_any(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_any<size_t>(session->connection, 0);
                    continue;
                }
                int type = *(node_head + NODE_HEAD_TYPE_OFFSET);
                delete[] node_head;
                if (type != NODE_TYPE_DIRECTORY) {
                    send_any(session->connection, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_any<size_t>(session->connection, 0);
                    continue;
                }
                std::ifstream node_data_file(get_node_data_path(node));
                std::string node_data((std::istreambuf_iterator<char>(node_data_file)),
                                      std::istreambuf_iterator<char>());
                send_any(session->connection, REQUEST_OK);
                send_any<size_t>(session->connection, node_data.size());
                send_exact(session->connection, node_data.size(), node_data.c_str());
            } else if (cmd == REQUEST_CMD_GOODBYE) {
                goodbye = true;
                send_any(session->connection, REQUEST_OK);
                send_any<size_t>(session->connection, size);
                send_exact(session->connection, size, body);
            } else {
                send_any(session->connection, REQUEST_ERR_INVALID_CMD);
                send_any<size_t>(session->connection, 0);
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

char *CloudServer::get_node_head(Node node) {
    std::string node_file_path = config.nodes_head_directory + PATH_DIV + node2string(node);
    if (!std::filesystem::is_regular_file(node_file_path)) return nullptr;
    std::ifstream node_file(node_file_path);
    std::string node_string((std::istreambuf_iterator<char>(node_file)), std::istreambuf_iterator<char>());
    char *node_head = new char[node_string.size() + 1];
    strcpy(node_head, node_string.c_str());
    return node_head;
}

std::string CloudServer::get_node_data_path(Node node) {
    return config.nodes_data_directory + PATH_DIV + node2string(node);
}

CloudServer::Session::Session(NetConnection *connection) : connection(connection) {

}
