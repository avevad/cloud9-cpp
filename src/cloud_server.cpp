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
    if (!config.access_log.empty()) {
        access_log.open(config.access_log, std::ios_base::out | std::ios_base::app);
    }
}

CloudServer::~CloudServer() {
    shutting_down = true;
    net->destroy();
    if (connector->joinable()) connector->join();
    delete connector;
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
            auto[user_head, user_size] = get_user_head(session->login);
            std::string salt(user_head + USER_HEAD_OFFSET_SALT, USER_PASSWORD_SALT_LENGTH);
            std::string password_salted = password + salt;
            char *sha256 = new char[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char *>(password_salted.c_str()), password_salted.length(),
                   reinterpret_cast<unsigned char *>(sha256));
            bool ok = memcmp(sha256, user_head + USER_HEAD_OFFSET_HASH, SHA256_DIGEST_LENGTH) == 0;
            delete[] user_head;
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
            auto id = read_uint32(session->connection);
            auto cmd = read_uint16(session->connection);
            auto size = read_uint64(session->connection);
            if (size > REQUEST_BODY_MAX_SIZE) {
                send_uint32(session->connection, id);
                send_uint16(session->connection, REQUEST_ERR_BODY_TOO_LARGE);
                send_uint64(session->connection, 0);
                throw std::runtime_error(request_status_string(REQUEST_ERR_BODY_TOO_LARGE));
            }
            delete[] body;
            body = new char[size];
            read_exact(session->connection, size, body);
            std::unique_lock global_locker(lock);
            std::unique_lock session_locker(session->lock);
            send_uint32(session->connection, id);
            if (cmd == REQUEST_CMD_GET_HOME) {
                std::string user = size == 0 ? session->login : std::string(body, size);
                log_request(session, cmd, std::pair("user", user));
                auto[user_head, user_size] = get_user_head(user);
                if (!user_head) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                } else {
                    Node home = *reinterpret_cast<const Node *>(user_head + USER_HEAD_OFFSET_HOME);
                    delete[] user_head;
                    log_response(session, std::pair("home", node2string(home)));
                    send_uint16(session->connection, REQUEST_OK);
                    send_uint64(session->connection, sizeof(Node));
                    send_exact(session->connection, sizeof(Node), &home);
                }
            } else if (cmd == REQUEST_CMD_LIST_DIRECTORY) {
                if (size != sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("dir", node2string(node)));
                auto[node_head, head_size] = get_node_head(node);
                if (!node_head) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t type = *(node_head + NODE_HEAD_OFFSET_TYPE);
                delete[] node_head;
                ReadWrite rights = get_user_rights(node, session->login);
                if (!rights.read) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (type != NODE_TYPE_DIRECTORY) {
                    log_error(session, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint16(session->connection, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::ifstream node_data_file(get_node_data_path(node));
                std::string node_data((std::istreambuf_iterator<char>(node_data_file)),
                                      std::istreambuf_iterator<char>());
                log_response(session, std::pair("dir_node_size", std::to_string(node_data.length())));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, node_data.size());
                send_exact(session->connection, node_data.size(), node_data.c_str());
            } else if (cmd == REQUEST_CMD_GOODBYE) {
                log_request(session, REQUEST_CMD_GOODBYE);
                goodbye = true;
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, size);
                send_exact(session->connection, size, body);
            } else if (cmd == REQUEST_CMD_GET_PARENT) {
                if (size != sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("node", node2string(node)));
                uint16_t error = REQUEST_OK;
                Node parent;
                bool ok = get_parent(node, parent, error);
                if (ok) {
                    log_response(session, std::pair("parent", node2string(parent)));
                    send_uint16(session->connection, REQUEST_OK);
                    send_uint64(session->connection, sizeof(Node));
                    send_exact(session->connection, sizeof(Node), &parent);
                } else {
                    if (error != REQUEST_OK) log_error(session, error);
                    else log_response(session, std::pair("parent", ""));
                    send_uint16(session->connection, error);
                    send_uint64(session->connection, 0);
                }
            } else if (cmd == REQUEST_CMD_MAKE_NODE) {
                if (size < sizeof(Node) + 1) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto name_len = *reinterpret_cast<uint8_t *>(body + sizeof(Node));
                if (sizeof(Node) + 1 + name_len + 1 != size) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t type = body[size - 1];
                std::string name(body + sizeof(Node) + 1, name_len);
                Node parent = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("name", name), std::pair("type", std::to_string(type)),
                            std::pair("parent", node2string(parent)));
                if (!is_valid_name(name)) {
                    log_error(session, REQUEST_ERR_INVALID_NAME);
                    send_uint16(session->connection, REQUEST_ERR_INVALID_NAME);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (type != NODE_TYPE_FILE && type != NODE_TYPE_DIRECTORY) {
                    log_error(session, REQUEST_ERR_INVALID_TYPE);
                    send_uint16(session->connection, REQUEST_ERR_INVALID_TYPE);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[parent_head, parent_head_size] = get_node_head(parent);
                if (!parent_head) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!get_user_rights(parent, session->login).write) {
                    delete[] parent_head;
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (*reinterpret_cast<uint8_t *>(parent_head + NODE_HEAD_OFFSET_TYPE) != NODE_TYPE_DIRECTORY) {
                    delete[] parent_head;
                    log_error(session, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint16(session->connection, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[parent_data, parent_data_size] = get_node_data(parent);
                {
                    auto *pos = parent_data;
                    bool exists = false;
                    while (pos < parent_data + parent_data_size) {
                        pos += sizeof(Node);
                        uint8_t child_name_len = *reinterpret_cast<uint8_t *>(pos);
                        pos++;
                        std::string child_name(pos, child_name_len);
                        if (child_name == name) {
                            exists = true;
                            break;
                        }
                        pos += child_name_len;
                    }
                    if (exists) {
                        delete[] parent_data;
                        delete[] parent_head;
                        log_error(session, REQUEST_ERR_EXISTS);
                        send_uint16(session->connection, REQUEST_ERR_EXISTS);
                        send_uint64(session->connection, 0);
                        continue;
                    }
                }
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
                    header += parent_head[NODE_HEAD_OFFSET_OWNER_GROUP_SIZE];
                    header += std::string(
                            parent_head + NODE_HEAD_OFFSET_OWNER_GROUP,
                            (size_t) *reinterpret_cast<uint8_t *>(parent_head + NODE_HEAD_OFFSET_OWNER_GROUP_SIZE)
                    );
                    header += std::string(reinterpret_cast<const char *>(&parent), sizeof(Node));
                    head_stream << header;
                }
                delete[] parent_head;
                log_response(session, std::pair("node", node2string(node)));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, sizeof(Node));
                send_exact(session->connection, sizeof(Node), &node);
            } else if (cmd == REQUEST_CMD_GET_NODE_OWNER) {
                if (size != sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("node", node2string(node)));
                if (!node_exists(node)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::string owner = get_node_owner(node);
                log_response(session, std::pair("owner", owner));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, owner.length());
                send_exact(session->connection, owner.length(), owner.c_str());
            } else if (cmd == REQUEST_CMD_FD_OPEN) {
                if (size != sizeof(Node) + 1) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("node", node2string(node)));
                if (!node_exists(node)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto *node_head = get_node_head(node).first;
                if (*reinterpret_cast<uint8_t *>(node_head + NODE_HEAD_OFFSET_TYPE) != NODE_TYPE_FILE) {
                    delete[] node_head;
                    log_error(session, REQUEST_ERR_NOT_A_FILE);
                    send_uint16(session->connection, REQUEST_ERR_NOT_A_FILE);
                    send_uint64(session->connection, 0);
                    continue;
                }
                delete[] node_head;
                uint8_t mode = *reinterpret_cast<uint8_t *>(body + sizeof(Node));
                bool read = mode & NODE_FD_MODE_READ;
                bool write = mode & NODE_FD_MODE_WRITE;
                ReadWrite rights = get_user_rights(node, session->login);
                if ((read && !rights.read) || (write && !rights.write)) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if ((read && writers[node]) || (write && (writers[node] || !readers[node].empty()))) {
                    log_error(session, REQUEST_ERR_BUSY);
                    send_uint16(session->connection, REQUEST_ERR_BUSY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                size_t fd;
                for (fd = 0; fd < session->fds.size(); fd++) {
                    if (!session->fds[fd].stream) break;
                }
                if (fd == session->fds.size()) {
                    if (fd > 0xFF) {
                        log_error(session, REQUEST_ERR_TOO_MANY_FDS);
                        send_uint16(session->connection, REQUEST_ERR_TOO_MANY_FDS);
                        send_uint64(session->connection, 0);
                        continue;
                    } else session->fds.emplace_back();
                }
                auto s_mode = std::ios_base::binary;
                if (read) s_mode |= std::ios_base::in;
                if (write) s_mode |= std::ios_base::out;
                auto *stream = new std::fstream(get_node_data_path(node), s_mode);
                session->fds[fd].node = node;
                session->fds[fd].stream = stream;
                session->fds[fd].mode = mode;
                if (read) readers[node].insert(session);
                if (write) writers[node] = session;
                log_response(session, std::pair("fd", std::to_string(fd)));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 1);
                send_uint8(session->connection, fd);
            } else if (cmd == REQUEST_CMD_FD_CLOSE) {
                if (size != 1) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t fd = *reinterpret_cast<uint8_t *>(body);
                log_request(session, cmd, std::pair("fd", std::to_string(fd)));
                if (fd >= session->fds.size()) {
                    log_error(session, REQUEST_ERR_BAD_FD);
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Session::FileDescriptor descriptor = session->fds[fd];
                if (!descriptor.stream) {
                    log_error(session, REQUEST_ERR_BAD_FD);
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                close_fd(session, descriptor);
                session->fds[fd].stream = nullptr;
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 1);
                send_uint8(session->connection, fd);
            } else if (cmd == REQUEST_CMD_FD_WRITE) {
                if (size < 1) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t fd = *reinterpret_cast<uint8_t *>(body);
                if (fd >= session->fds.size()) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Session::FileDescriptor descriptor = session->fds[fd];
                if (!descriptor.stream) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!(descriptor.mode & NODE_FD_MODE_WRITE)) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_SUPPORTED);
                    send_uint64(session->connection, 0);
                    continue;
                }
                descriptor.stream->write(body + 1, size - 1);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else if (cmd == REQUEST_CMD_FD_READ) {
                if (size != 1 + sizeof(uint32_t)) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t fd = *reinterpret_cast<uint8_t *>(body);
                if (fd >= session->fds.size()) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Session::FileDescriptor descriptor = session->fds[fd];
                if (!descriptor.stream) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!(descriptor.mode & NODE_FD_MODE_READ)) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_SUPPORTED);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (descriptor.stream->eof()) {
                    send_uint16(session->connection, REQUEST_ERR_END_OF_FILE);
                    send_uint64(session->connection, 0);
                    continue;
                } else {
                    uint32_t count = buf_read_uint32(body + 1);
                    if (count > MAX_READ_BLOCK_SIZE) {
                        send_uint16(session->connection, REQUEST_ERR_READ_BLOCK_IS_TOO_LARGE);
                        send_uint64(session->connection, 0);
                        continue;
                    } else {
                        char *buffer = new char[count];
                        descriptor.stream->read(buffer, count);
                        uint32_t read = descriptor.stream->gcount();
                        try {
                            send_uint16(session->connection, REQUEST_OK);
                            send_uint64(session->connection, read);
                            send_exact(session->connection, read, buffer);
                        } catch (...) {
                            delete[] buffer;
                            throw;
                        }
                        delete[] buffer;
                    }
                }
            } else if (cmd == REQUEST_CMD_GET_NODE_INFO) {
                if (size != sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("node", node2string(node)));
                if (!node_exists(node)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[node_head, node_size] = get_node_head(node);
                uint8_t file_type = *reinterpret_cast<uint8_t *>(node_head + NODE_HEAD_OFFSET_TYPE);
                uint8_t file_rights = *reinterpret_cast<uint8_t *>(node_head + NODE_HEAD_OFFSET_RIGHTS);
                delete[] node_head;
                uint64_t file_size = std::filesystem::file_size(get_node_data_path(node));
                log_response(session,
                             std::pair("type", std::to_string(file_type)),
                             std::pair("size", std::to_string(file_size)),
                             std::pair("rights", rights2string(file_rights)));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint8_t));
                send_uint8(session->connection, file_type);
                send_uint64(session->connection, file_size);
                send_uint8(session->connection, file_rights);
            } else if (cmd == REQUEST_CMD_FD_READ_LONG) {
                if (size != 1 + sizeof(uint64_t)) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t fd = *reinterpret_cast<uint8_t *>(body);
                uint64_t count = buf_read_uint64(body + 1);
                if (fd >= session->fds.size()) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Session::FileDescriptor descriptor = session->fds[fd];
                if (!descriptor.stream) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!(descriptor.mode & NODE_FD_MODE_READ)) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_SUPPORTED);
                    send_uint64(session->connection, 0);
                    continue;
                }
                {
                    uint64_t pos = descriptor.stream->tellg();
                    descriptor.stream->seekg(0, std::fstream::end);
                    uint64_t length = descriptor.stream->tellg();
                    descriptor.stream->seekg(pos, std::fstream::beg);
                    if (pos + count > length) {
                        send_uint16(session->connection, REQUEST_ERR_END_OF_FILE);
                        send_uint64(session->connection, 0);
                    }
                }
                send_uint16(session->connection, REQUEST_SWITCH_OK);
                send_uint64(session->connection, 0);
                global_locker.unlock();
                char *buffer = new char[MAX_READ_BLOCK_SIZE];
                uint64_t done = 0;
                try {
                    while (done < count) {
                        uint32_t read = std::min(count - done, uint64_t(MAX_READ_BLOCK_SIZE));
                        descriptor.stream->read(buffer, read);
                        send_exact(session->connection, read, buffer);
                        done += uint64_t(read);
                    }
                } catch (...) {
                    delete[] buffer;
                    throw;
                }
                delete[] buffer;
            } else if (cmd == REQUEST_CMD_FD_WRITE_LONG) {
                if (size != 1 + sizeof(uint64_t)) {
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                uint8_t fd = *reinterpret_cast<uint8_t *>(body);
                uint64_t count = buf_read_uint64(body + 1);
                if (fd >= session->fds.size()) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Session::FileDescriptor descriptor = session->fds[fd];
                if (!descriptor.stream) {
                    send_uint16(session->connection, REQUEST_ERR_BAD_FD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!(descriptor.mode & NODE_FD_MODE_WRITE)) {
                    send_uint16(session->connection, REQUEST_ERR_NOT_SUPPORTED);
                    send_uint64(session->connection, 0);
                    continue;
                }
                send_uint16(session->connection, REQUEST_SWITCH_OK);
                send_uint64(session->connection, 0);
                global_locker.unlock();
                uint64_t done = 0;
                char *buffer = new char[MAX_READ_BLOCK_SIZE];
                try {
                    while (done < count) {
                        uint64_t read = session->connection->read(std::min(count - done, uint64_t(MAX_READ_BLOCK_SIZE)),
                                                                  buffer);
                        descriptor.stream->write(buffer, read);
                        done += read;
                    }
                } catch (...) {
                    delete[] buffer;
                    throw;
                }
                delete[] buffer;
            } else if (cmd == REQUEST_CMD_SET_NODE_RIGHTS) {
                if (size != sizeof(Node) + 1) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                uint8_t rights = *reinterpret_cast<uint8_t *>(body + sizeof(Node));
                rights &= uint8_t(NODE_RIGHTS_GROUP_READ | NODE_RIGHTS_GROUP_WRITE | NODE_RIGHTS_ALL_READ |
                                  NODE_RIGHTS_ALL_WRITE);
                log_request(session, cmd, std::pair("node", node2string(node)),
                            std::pair("rights", rights2string(rights)));
                if (!node_exists(node)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (get_node_owner(node) != session->login) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[node_head, node_size] = get_node_head(node);
                std::ofstream node_stream(get_node_head_path(node));
                *(reinterpret_cast<uint8_t *>(node_head + NODE_HEAD_OFFSET_RIGHTS)) = rights;
                node_stream.write(node_head, node_size);
                delete[] node_head;
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else if (cmd == REQUEST_CMD_GROUP_INVITE) {
                std::string user(body, size);
                log_request(session, cmd, std::pair("user", user));
                if (!std::filesystem::exists(get_user_head_path(user))) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (is_member(user, session->login)) {
                    log_error(session, REQUEST_ERR_EXISTS);
                    send_uint16(session->connection, REQUEST_ERR_EXISTS);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::ofstream user_file(get_user_head_path(user), std::fstream::out | std::fstream::app);
                uint8_t length = session->login.length();
                user_file.write(reinterpret_cast<char *>(&length), 1);
                user_file << session->login;
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else if (cmd == REQUEST_CMD_GET_NODE_GROUP) {
                if (size != sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("node", node2string(node)));
                auto[node_head, node_size] = get_node_head(node);
                if (!node_head) {
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::string group = get_node_group(node_head);
                delete[] node_head;
                log_response(session, std::pair("group", group));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, group.length());
                send_exact(session->connection, group.length(), group.c_str());
            } else if (cmd == REQUEST_CMD_DELETE_NODE) {
                if (size != sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                log_request(session, cmd, std::pair("node", node2string(node)));
                // node doesnt exists
                if (!node_exists(node)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // node is nonempty dir
                auto[node_head, node_head_size] = get_node_head(node);
                auto[node_data, node_data_size] = get_node_data(node);
                uint8_t type = *(node_head + NODE_HEAD_OFFSET_TYPE);
                delete[] node_head;
                delete[] node_data;
                if ((type == NODE_TYPE_DIRECTORY) && node_data_size) {
                    log_error(session, REQUEST_ERR_DIR_NOT_EMPTY);
                    send_uint16(session->connection, REQUEST_ERR_DIR_NOT_EMPTY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // no rights
                if (!get_user_rights(node, session->login).write) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // is home
                uint16_t error = REQUEST_OK;
                Node parent;
                bool ok = get_parent(node, parent, error);
                if (!ok) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // cut parent link to node
                auto[parent_head, parent_head_size] = get_node_head(parent);
                auto[parent_data, parent_data_size] = get_node_data(parent);
                ssize_t cut_pos = -1, cut_sz = -1;
                {
                    auto *pos = parent_data;
                    uint8_t child_name_len;
                    while (pos < parent_data + parent_data_size) {
                        Node child = *reinterpret_cast<Node *>(pos);
                        pos += sizeof(Node);
                        child_name_len = *reinterpret_cast<uint8_t *>(pos);
                        pos++;
                        pos += child_name_len;
                        if (child == node) {
                            cut_pos = pos - child_name_len - 1 - sizeof(Node) - parent_data;
                            cut_sz = pos - parent_data - cut_pos;
                            break;
                        }
                    }
                    if (cut_pos == -1) {
                        delete[] parent_data;
                        delete[] parent_head;
                        log_error(session, REQUEST_ERR_EXISTS);
                        send_uint16(session->connection, REQUEST_ERR_EXISTS);
                        send_uint64(session->connection, 0);
                        continue;
                    }
                }
                std::string parent_data_string(parent_data, parent_data_size);
                std::string new_parent_data_string =
                        parent_data_string.substr(0, cut_pos) +
                        parent_data_string.substr(cut_pos + cut_sz, parent_data_string.size() - cut_pos - cut_sz);
                delete[] parent_data;
                delete[] parent_head;
                {
                    std::ofstream parent_data_file(get_node_data_path(parent));
                    parent_data_file << new_parent_data_string;
                }
                // del files char/data
                std::filesystem::remove(get_node_data_path(node));
                std::filesystem::remove(get_node_head_path(node));
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else if (cmd == REQUEST_CMD_SET_NODE_GROUP) {
                if (size <= sizeof(Node)) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                std::string group(body + sizeof(Node), body + size);
                log_request(session, cmd, std::pair("node", node2string(node)), std::pair("group", group));
                auto[node_head_ptr, node_size] = get_node_head(node);
                if (!node_head_ptr) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::string node_head(node_head_ptr, node_size);
                delete[] node_head_ptr;
                if (get_node_owner(node) != session->login) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!is_member(session->login, group)) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                std::string node_head1 = node_head.substr(0, NODE_HEAD_OFFSET_OWNER_GROUP_SIZE);
                std::string node_head2 = node_head.substr(
                        NODE_HEAD_OFFSET_OWNER_GROUP + get_node_group(node_head.c_str()).length());
                std::string node_head0 = " " + group;
                node_head0[0] = group.length();
                node_head = node_head1 + node_head0 + node_head2;
                std::ofstream node_head_file(get_node_head_path(node));
                node_head_file << node_head;
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else if (cmd == REQUEST_CMD_GROUP_KICK) {
                std::string user(body, size);
                log_request(session, cmd, std::pair("user", user));
                if (user == session->login) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!is_member(user, session->login)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                remove_from_group(session->login, user);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else if (cmd == REQUEST_CMD_GROUP_LIST) {
                log_request(session, cmd);
                if (size != 0) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                auto[head, size] = get_user_head(session->login);
                std::string groups(head + USER_HEAD_OFFSET_GROUPS, head + size);
                log_response(session, std::pair("groups_size", std::to_string(groups.length())));
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, groups.length());
                send_exact(session->connection, groups.length(), groups.c_str());
            } else if (cmd == REQUEST_CMD_MOVE_NODE) {
                if (size != sizeof(Node) * 2) {
                    log_request(session, cmd);
                    log_error(session, REQUEST_ERR_MALFORMED_CMD);
                    send_uint16(session->connection, REQUEST_ERR_MALFORMED_CMD);
                    send_uint64(session->connection, 0);
                    continue;
                }
                Node node = *reinterpret_cast<Node *>(body);
                Node new_parent = *reinterpret_cast<Node *>(body + sizeof(Node));
                log_request(session, cmd, std::pair("node", node2string(node)));
                // nodes doesnt exists
                if (!node_exists(node)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                if (!node_exists(new_parent)) {
                    log_error(session, REQUEST_ERR_NOT_FOUND);
                    send_uint16(session->connection, REQUEST_ERR_NOT_FOUND);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // new_parent is dir
                auto[np_head, np_head_size] = get_node_head(new_parent);
                uint8_t type = *(np_head + NODE_HEAD_OFFSET_TYPE);
                delete[] np_head;
                if (type != NODE_TYPE_DIRECTORY) {
                    log_error(session, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint16(session->connection, REQUEST_ERR_NOT_A_DIRECTORY);
                    send_uint64(session->connection, 0);
                    continue;
                }
                //no rights
                if (!get_user_rights(node, session->login).write || 
                    !get_user_rights(new_parent, session->login).write) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // node is home
                uint16_t error = REQUEST_OK;
                Node parent;
                bool ok = get_parent(node, parent, error);
                if (!ok) {
                    log_error(session, REQUEST_ERR_FORBIDDEN);
                    send_uint16(session->connection, REQUEST_ERR_FORBIDDEN);
                    send_uint64(session->connection, 0);
                    continue;
                }
                // cut parent link to node
                auto[parent_head, parent_head_size] = get_node_head(parent);
                auto[parent_data, parent_data_size] = get_node_data(parent);
                ssize_t cut_pos = -1, cut_sz = -1;
                {
                    uint8_t child_name_len;
                    auto *pos = parent_data;
                    while (pos < parent_data + parent_data_size) {
                        Node child = *reinterpret_cast<Node *>(pos);
                        pos += sizeof(Node);
                        child_name_len = *reinterpret_cast<uint8_t *>(pos);
                        pos++;
                        pos += child_name_len;
                        if (child == node) {
                            cut_pos = pos - child_name_len - 1 - sizeof(Node) - parent_data;
                            cut_sz = pos - parent_data - cut_pos;
                            break;
                        }
                    }
                    if (cut_pos == -1) {
                        delete[] parent_data;
                        delete[] parent_head;
                        log_error(session, REQUEST_ERR_EXISTS);
                        send_uint16(session->connection, REQUEST_ERR_EXISTS);
                        send_uint64(session->connection, 0);
                        continue;
                    }
                }
                std::string parent_data_string(parent_data, parent_data_size);
                std::string new_parent_data_string =
                        parent_data_string.substr(0, cut_pos) +
                        parent_data_string.substr(cut_pos + cut_sz, parent_data_string.size() - cut_pos - cut_sz);
                std::string about_node = parent_data_string.substr(cut_pos, cut_sz);
                delete[] parent_head;
                {
                    std::ofstream parent_data_file(get_node_data_path(parent));
                    parent_data_file << new_parent_data_string;
                }
                // add link of new_parent to node
                auto[np_data, np_data_size] = get_node_data(new_parent);
                std::string np_data_string(np_data, np_data_size);
                delete[] np_data;
                np_data_string += about_node;
                std::cerr << np_data_string << std::endl;
                {
                    std::ofstream np_data_file(get_node_data_path(new_parent));
                    np_data_file << np_data_string;
                }
                delete[] parent_data;
                log_response(session);
                send_uint16(session->connection, REQUEST_OK);
                send_uint64(session->connection, 0);
            } else {
                log_request(session, cmd);
                log_error(session, REQUEST_ERR_INVALID_CMD);
                send_uint16(session->connection, REQUEST_ERR_INVALID_CMD);
                send_uint64(session->connection, 0);
            }
        }
    } catch (std::exception &exception) {
        if (!shutting_down && !goodbye)
            std::cerr << "'" << session->login << "' listener stopped with exception: " << exception.what()
                      << std::endl;
    }
    std::unique_lock locker(lock);
    for (Session::FileDescriptor fd : session->fds) {
        if (fd.stream) close_fd(session, fd);
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
    std::string owner = get_node_owner(node);
    if (owner == user) user_rights.read = user_rights.write = true;
    if (is_member(user, get_node_group(node_head))) {
        if (rights & NODE_RIGHTS_GROUP_READ) user_rights.read = true;
        if (rights & NODE_RIGHTS_GROUP_WRITE) user_rights.write = true;
    }
    if (rights & NODE_RIGHTS_ALL_READ) user_rights.read = true;
    if (rights & NODE_RIGHTS_ALL_WRITE) user_rights.write = true;
    delete[] node_head;
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
    delete[] node_head;
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
    do {
        for (unsigned char &b : node.id)
            b = std::rand() % 0xFF;
    } while (std::filesystem::is_regular_file(get_node_data_path(node)));
    return node;
}

std::string CloudServer::get_node_head_path(Node node) {
    return config.nodes_head_directory + PATH_DIV + node2string(node);
}

std::string CloudServer::get_node_owner(Node node) {
    Node home = node;
    uint16_t error;
    while (get_parent(home, home, error));
    std::string owner;
    get_home_owner(home, error, owner);
    return owner;
}

bool CloudServer::node_exists(Node node) {
    return std::filesystem::is_regular_file(get_node_head_path(node));
}

void CloudServer::close_fd(Session *session, CloudServer::Session::FileDescriptor fd) {
    delete fd.stream;
    if (fd.mode & NODE_FD_MODE_READ) readers[fd.node].erase(session);
    if (fd.mode & NODE_FD_MODE_WRITE) writers[fd.node] = nullptr;
}

std::string CloudServer::get_user_head_path(const std::string &user) {
    return config.users_directory + PATH_DIV + user;
}

std::pair<const char *, size_t> CloudServer::get_user_head(const std::string &user) {
    std::string user_file_path = get_user_head_path(user);
    if (!std::filesystem::exists(user_file_path)) return {nullptr, 0};
    std::ifstream user_file(user_file_path);
    std::string user_string((std::istreambuf_iterator<char>(user_file)), std::istreambuf_iterator<char>());
    char *ret = new char[user_string.size()];
    memcpy(ret, user_string.c_str(), user_string.size());
    return {ret, user_string.size()};
}

bool CloudServer::is_member(const std::string &user, const std::string &group) {
    if (user == group) return true;
    auto[user_head, user_size] = get_user_head(user);
    const char *ptr = user_head + USER_HEAD_OFFSET_GROUPS;
    bool res = false;
    while (ptr < user_head + user_size) {
        uint8_t length = *reinterpret_cast<const uint8_t *>(ptr);
        ptr++;
        std::string cur_group(ptr, length);
        if (cur_group == group) {
            res = true;
            break;
        }
        ptr += length;
    }
    delete[] user_head;
    return res;
}

std::string CloudServer::get_node_group(const char *node_head) {
    return std::string(node_head + NODE_HEAD_OFFSET_OWNER_GROUP,
                       (size_t) *reinterpret_cast<const uint8_t *>(node_head + NODE_HEAD_OFFSET_OWNER_GROUP_SIZE));
}

void CloudServer::remove_from_group(const std::string &group, const std::string &user) {
    auto[head_p, size] = get_user_head(user);
    std::string head(head_p, size);
    delete[] head_p;
    size_t pos = USER_HEAD_OFFSET_GROUPS;
    while (pos < size) {
        uint8_t length = head[pos];
        pos++;
        if (head.substr(pos, length) == group) {
            std::ofstream head_stream(get_user_head_path(user));
            head_stream << head.substr(0, pos - 1) << head.substr(pos + length);
            return;
        }
        pos += length;
    }
}

CloudServer::Session::Session(NetConnection *connection) : connection(connection) {

}
