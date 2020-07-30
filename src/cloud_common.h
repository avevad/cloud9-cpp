#ifndef CLOUD9_CLOUD_COMMON_H
#define CLOUD9_CLOUD_COMMON_H

#include <string>
#include <cstring>
#include <algorithm>
#include <chrono>
#include "networking.h"

static size_t DEFAULT_NET_BUFFER_SIZE = 1024 * 1024; // 1 MiB
static size_t DEFAULT_DATA_BUFFER_SIZE = 1024 * 640; // 640 KiB

static void read_exact(NetConnection *connection, uint64_t size, void *buffer) {
    uint64_t read = 0;
    while (read < size) read += connection->read(size - read, reinterpret_cast<char *>(buffer) + read);
}

static void send_exact(NetConnection *connection, uint64_t size, const void *buffer) {
    uint64_t sent = 0;
    while (sent < size) sent += connection->send(size - sent, reinterpret_cast<const char *>(buffer) + sent);
}

static void send_uint8(NetConnection *connection, uint8_t n) {
    send_exact(connection, 1, &n);
}

static uint8_t read_uint8(NetConnection *connection) {
    uint8_t n;
    read_exact(connection, 1, &n);
    return n;
}

static void send_uint16(NetConnection *connection, uint16_t n) {
    uint8_t buffer[2];
    for (int8_t i = 1; i >= 0; i--) {
        buffer[i] = n & uint16_t(0xFF);
        n >>= uint16_t(8);
    }
    send_exact(connection, 2, &buffer);
}

static uint16_t read_uint16(NetConnection *connection) {
    uint8_t buffer[2];
    read_exact(connection, 2, &buffer);
    uint16_t n = 0;
    for (uint8_t e : buffer) {
        n <<= uint16_t(8);
        n |= uint16_t(e);
    }
    return n;
}

static void send_uint32(NetConnection *connection, uint32_t n) {
    uint8_t buffer[4];
    for (int8_t i = 3; i >= 0; i--) {
        buffer[i] = n & uint32_t(0xFF);
        n >>= uint32_t(8);
    }
    send_exact(connection, 4, &buffer);
}

static uint32_t buf_read_uint32(void *buffer) {
    auto *r_buffer = reinterpret_cast<uint8_t *>(buffer);
    uint32_t n = 0;
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        uint8_t e = r_buffer[i];
        n <<= uint32_t(8);
        n |= uint32_t(e);
    }
    return n;
}

static uint32_t read_uint32(NetConnection *connection) {
    uint8_t buffer[4];
    read_exact(connection, 4, &buffer);
    return buf_read_uint32(buffer);
}

static void send_uint64(NetConnection *connection, uint64_t n) {
    uint8_t buffer[8];
    for (int8_t i = 7; i >= 0; i--) {
        buffer[i] = n & uint64_t(0xFF);
        n >>= uint64_t(8);
    }
    send_exact(connection, 8, &buffer);
}

static uint64_t buf_read_uint64(void *buffer) {
    auto *r_buffer = reinterpret_cast<uint8_t *>(buffer);
    uint64_t n = 0;
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        uint8_t e = r_buffer[i];
        n <<= uint64_t(8);
        n |= uint64_t(e);
    }
    return n;
}

static uint64_t read_uint64(NetConnection *connection) {
    uint8_t buffer[8];
    read_exact(connection, 8, &buffer);
    return buf_read_uint64(&buffer);
}

#define NODE_ID_LENGTH 16

typedef struct {
    uint8_t id[NODE_ID_LENGTH];
} Node;

static bool is_number(const std::string &s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

static const char *LOGIN_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

static bool is_valid_login(const std::string &login) {
    if (login.length() <= 0) return false;
    for (char c : login) {
        const char *end = LOGIN_CHARSET + strlen(LOGIN_CHARSET);
        if (std::find(LOGIN_CHARSET, end, c) == end) return false;
    }
    return true;
}

static const char CLOUD_PATH_DIV = '/';
static const char CLOUD_PATH_HOME = '~';
static const char CLOUD_PATH_NODE = '#';
static const char CLOUD_PATH_UNKNOWN = '?';

static bool is_valid_name(const std::string &name) {
    if (name.length() <= 0 || name.length() > 0xFF) return false;
    if (name == ".." | name == ".") return false;
    for (char c : name) {
        if (c == CLOUD_PATH_DIV || c == CLOUD_PATH_HOME || c == CLOUD_PATH_NODE || c == CLOUD_PATH_UNKNOWN)
            return false;
    }
    return true;
}

static const uint16_t CLOUD_DEFAULT_PORT = 909;

static const char PATH_DIV = '/';
static const char LOGIN_DIV = '@';

static const uint64_t INIT_BODY_MAX_SIZE = 1024 * 8; // 8 KiB

static const uint16_t INIT_CMD_AUTH = 1;
static const uint16_t INIT_CMD_REGISTER = 2;

static const uint16_t INIT_OK = 0;
static const uint16_t INIT_ERR_BODY_TOO_LARGE = 1;
static const uint16_t INIT_ERR_INVALID_CMD = 2;
static const uint16_t INIT_ERR_AUTH_FAILED = 3;
static const uint16_t INIT_ERR_MALFORMED_CMD = 4;
static const uint16_t INIT_ERR_INVALID_INVITE_CODE = 5;
static const uint16_t INIT_ERR_USER_EXISTS = 6;

static const uint64_t REQUEST_BODY_MAX_SIZE = 1024 * 1024 * 8; // 8 MiB
static const uint16_t REQUEST_CMD_GET_HOME = 1;
static const uint16_t REQUEST_CMD_LIST_DIRECTORY = 2;
static const uint16_t REQUEST_CMD_GOODBYE = 3;
static const uint16_t REQUEST_CMD_GET_PARENT = 4;
static const uint16_t REQUEST_CMD_MAKE_NODE = 5;
static const uint16_t REQUEST_CMD_GET_NODE_OWNER = 6;
static const uint16_t REQUEST_CMD_FD_OPEN = 7;
static const uint16_t REQUEST_CMD_FD_CLOSE = 8;
static const uint16_t REQUEST_CMD_FD_READ = 9;
static const uint16_t REQUEST_CMD_FD_WRITE = 10;
static const uint16_t REQUEST_CMD_GET_NODE_INFO = 11;
static const uint16_t REQUEST_CMD_FD_READ_LONG = 12;
static const uint16_t REQUEST_CMD_FD_WRITE_LONG = 13;
static const uint16_t REQUEST_CMD_SET_NODE_RIGHTS = 14;
static const uint16_t REQUEST_CMD_GET_NODE_GROUP = 15;
static const uint16_t REQUEST_CMD_SET_NODE_GROUP = 16;
static const uint16_t REQUEST_CMD_GROUP_INVITE = 17;
static const uint16_t REQUEST_CMD_REMOVE_NODE = 18;
static const uint16_t REQUEST_CMD_GROUP_KICK = 19;
static const uint16_t REQUEST_CMD_GROUP_LIST = 20;
static const uint16_t REQUEST_CMD_COPY_NODE = 21;
static const uint16_t REQUEST_CMD_MOVE_NODE = 22;
static const uint16_t REQUEST_CMD_RENAME_NODE = 23;

static const uint16_t REQUEST_OK = 0;
static const uint16_t REQUEST_ERR_BODY_TOO_LARGE = 1;
static const uint16_t REQUEST_ERR_INVALID_CMD = 2;
static const uint16_t REQUEST_ERR_MALFORMED_CMD = 3;
static const uint16_t REQUEST_ERR_NOT_FOUND = 4;
static const uint16_t REQUEST_ERR_NOT_A_DIRECTORY = 5;
static const uint16_t REQUEST_ERR_FORBIDDEN = 6;
static const uint16_t REQUEST_ERR_INVALID_NAME = 7;
static const uint16_t REQUEST_ERR_INVALID_TYPE = 8;
static const uint16_t REQUEST_ERR_EXISTS = 9;
static const uint16_t REQUEST_ERR_BUSY = 10;
static const uint16_t REQUEST_ERR_NOT_A_FILE = 11;
static const uint16_t REQUEST_ERR_TOO_MANY_FDS = 12;
static const uint16_t REQUEST_ERR_BAD_FD = 13;
static const uint16_t REQUEST_ERR_END_OF_FILE = 14;
static const uint16_t REQUEST_ERR_NOT_SUPPORTED = 15;
static const uint16_t REQUEST_ERR_READ_BLOCK_IS_TOO_LARGE = 16;
static const uint16_t REQUEST_SWITCH_OK = 17;
static const uint16_t REQUEST_ERR_DIRECTORY_IS_NOT_EMPTY = 18;

static const uint64_t USER_PASSWORD_SALT_LENGTH = 32;
static std::string USER_PASSWORD_SALT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static std::string generate_salt() {
    std::string salt(USER_PASSWORD_SALT_LENGTH, ' ');
    for (size_t i = 0; i < USER_PASSWORD_SALT_LENGTH; i++) {
        salt[i] = USER_PASSWORD_SALT_CHARSET[rand() % USER_PASSWORD_SALT_CHARSET.length()];
    }
    return salt;
}

static const uint64_t USER_HEAD_OFFSET_SALT = 0;
static const uint64_t USER_HEAD_OFFSET_HASH = USER_PASSWORD_SALT_LENGTH;
static const uint64_t USER_HEAD_OFFSET_HOME = USER_HEAD_OFFSET_HASH + SHA256_DIGEST_LENGTH;
static const uint64_t USER_HEAD_OFFSET_GROUPS = USER_HEAD_OFFSET_HOME + sizeof(Node);

static const uint64_t NODE_HEAD_OFFSET_TYPE = 0;
static const uint64_t NODE_HEAD_OFFSET_RIGHTS = 1;
static const uint64_t NODE_HEAD_OFFSET_OWNER_GROUP_SIZE = 2;
static const uint64_t NODE_HEAD_OFFSET_OWNER_GROUP = 3;

static const uint8_t NODE_FD_MODE_READ = 0b10;
static const uint8_t NODE_FD_MODE_WRITE = 0b01;

static const uint8_t NODE_RIGHTS_GROUP_READ = 0b1000;
static const uint8_t NODE_RIGHTS_GROUP_WRITE = 0b0100;
static const uint8_t NODE_RIGHTS_ALL_READ = 0b0010;
static const uint8_t NODE_RIGHTS_ALL_WRITE = 0b0001;

static const uint8_t NODE_TYPE_FILE = 0;
static const uint8_t NODE_TYPE_DIRECTORY = 1;

static std::string init_status_string(uint16_t status) {
    if (status == INIT_OK) return "init OK";
    else if (status == INIT_ERR_BODY_TOO_LARGE) return "init body is too large";
    else if (status == INIT_ERR_INVALID_CMD) return "unknown init command";
    else if (status == INIT_ERR_AUTH_FAILED) return "access denied";
    else if (status == INIT_ERR_MALFORMED_CMD) return "malformed init command";
    else if (status == INIT_ERR_INVALID_INVITE_CODE) return "invite code is invalid";
    else if (status == INIT_ERR_USER_EXISTS) return "user exists";
    else return "unknown init error (" + std::to_string(status) + ")";
}

static std::string request_status_string(uint16_t status) {
    if (status == REQUEST_OK) return "request OK";
    else if (status == REQUEST_ERR_BODY_TOO_LARGE) return "request body is too large";
    else if (status == REQUEST_ERR_INVALID_CMD) return "unknown request";
    else if (status == REQUEST_ERR_MALFORMED_CMD) return "malformed request";
    else if (status == REQUEST_ERR_NOT_FOUND) return "not found";
    else if (status == REQUEST_ERR_NOT_A_DIRECTORY) return "not a directory";
    else if (status == REQUEST_ERR_FORBIDDEN) return "access denied";
    else if (status == REQUEST_ERR_INVALID_NAME) return "invalid name";
    else if (status == REQUEST_ERR_INVALID_TYPE) return "invalid type";
    else if (status == REQUEST_ERR_EXISTS) return "object exists";
    else if (status == REQUEST_ERR_BUSY) return "resource busy";
    else if (status == REQUEST_ERR_NOT_A_FILE) return "not a regular file";
    else if (status == REQUEST_ERR_TOO_MANY_FDS) return "too many open files";
    else if (status == REQUEST_ERR_BAD_FD) return "bad file descriptor";
    else if (status == REQUEST_ERR_END_OF_FILE) return "end of file";
    else if (status == REQUEST_ERR_NOT_SUPPORTED) return "operation not supported";
    else if (status == REQUEST_ERR_READ_BLOCK_IS_TOO_LARGE) return "block size is too big";
    else if (status == REQUEST_SWITCH_OK) return "switching to long data transfer mode";
    else if (status == REQUEST_ERR_DIRECTORY_IS_NOT_EMPTY) return "directory is not empty";
    else return "unknown request error (" + std::to_string(status) + ")";
}

static std::string request_name(uint16_t request) {
    if (request == REQUEST_CMD_GET_HOME) return "HOME";
    else if (request == REQUEST_CMD_LIST_DIRECTORY) return "LIST";
    else if (request == REQUEST_CMD_GOODBYE) return "TERM";
    else if (request == REQUEST_CMD_GET_PARENT) return "GPAR";
    else if (request == REQUEST_CMD_MAKE_NODE) return "MAKE";
    else if (request == REQUEST_CMD_GET_NODE_OWNER) return "GOWN";
    else if (request == REQUEST_CMD_FD_OPEN) return "FDOP";
    else if (request == REQUEST_CMD_FD_CLOSE) return "FDCL";
    else if (request == REQUEST_CMD_FD_READ) return "FDRD";
    else if (request == REQUEST_CMD_FD_WRITE) return "FDWR";
    else if (request == REQUEST_CMD_GET_NODE_INFO) return "NINF";
    else if (request == REQUEST_CMD_FD_READ_LONG) return "FDRL";
    else if (request == REQUEST_CMD_FD_WRITE_LONG) return "FDWL";
    else if (request == REQUEST_CMD_SET_NODE_RIGHTS) return "SRGH";
    else if (request == REQUEST_CMD_REMOVE_NODE) return "REMV";
    else if (request == REQUEST_CMD_GET_NODE_GROUP) return "GGRP";
    else if (request == REQUEST_CMD_SET_NODE_GROUP) return "SGRP";
    else if (request == REQUEST_CMD_GROUP_INVITE) return "INVT";
    else if (request == REQUEST_CMD_GROUP_KICK) return "KICK";
    else if (request == REQUEST_CMD_GROUP_LIST) return "GLST";
    else if (request == REQUEST_CMD_COPY_NODE) return "COPY";
    else if (request == REQUEST_CMD_MOVE_NODE) return "MOVE";
    else if (request == REQUEST_CMD_MOVE_NODE) return "RENM";
    else return std::to_string(request);
}

static bool operator==(const Node &a, const Node &b) {
    return std::memcmp(&a, &b, sizeof(Node)) == 0;
}

static bool operator!=(const Node &a, const Node &b) {
    return std::memcmp(&a, &b, sizeof(Node)) != 0;
}

static bool operator<(const Node &a, const Node &b) {
    return std::memcmp(&a, &b, sizeof(Node)) < 0;
}

static std::string node2string(Node node) {
    std::string s(NODE_ID_LENGTH * 2, 0);
    for (uint64_t i = 0; i < NODE_ID_LENGTH; i++) {
        uint8_t d1 = node.id[i] / 0x10u;
        uint8_t d2 = node.id[i] & 0xFu;
        s[i * 2] = d1 < 10 ? ('0' + d1) : ('a' - 10 + d1);
        s[i * 2 + 1] = d2 < 10 ? ('0' + d2) : ('a' - 10 + d2);
    }
    return s;
}

static Node string2node(const std::string &s) {
    if (s.length() != 2 * NODE_ID_LENGTH) throw std::invalid_argument("invalid node string '" + s + "'");
    Node node;
    for (uint64_t i = 0; i < NODE_ID_LENGTH; i++) {
        auto c1 = s[i * 2];
        auto c2 = s[i * 2 + 1];
        unsigned d1;
        if (c1 >= '0' && c1 <= '9') {
            d1 = c1 - '0';
        } else if (c1 >= 'a' && c1 <= 'f') {
            d1 = c1 - 'a' + 10;
        } else if (c1 >= 'A' && c1 <= 'F') {
            d1 = c1 - 'A' + 10;
        } else throw std::invalid_argument("invalid node string '" + s + "'");
        unsigned d2;
        if (c2 >= '0' && c2 <= '9') {
            d2 = c2 - '0';
        } else if (c2 >= 'a' && c2 <= 'f') {
            d2 = c2 - 'a' + 10;
        } else if (c2 >= 'A' && c2 <= 'F') {
            d2 = c2 - 'A' + 10;
        } else throw std::invalid_argument("invalid node string '" + s + "'");
        node.id[i] = d1 * 0x10 + d2;
    }
    return node;
}

static std::pair<double, std::string> human_readable_size(size_t n, size_t base = 1000) {
    const char *prefixes = " kMGTPEZY";
    double m = n;
    const char *prefix = prefixes;
    while (m > base && *(prefix + 1) != '\0') {
        m /= double(base);
        prefix++;
    }
    return {m, (prefix == prefixes) ? std::string() : std::string(1, *prefix)};
}

static std::string human_readable_time(size_t time_s) {
    std::string h = std::to_string(time_s / 3600);
    if (h.size() < 2) h = "0" + h;
    std::string m = std::to_string((time_s / 60) % 60);
    if (m.size() < 2) m = "0" + m;
    std::string s = std::to_string(time_s % 60);
    if (s.size() < 2) s = "0" + s;
    return h + ":" + m + ":" + s;
}


static size_t get_current_time_ms() {
    return
            std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
            ).count();
}

static std::string rights2string(uint8_t rights) {
    return std::string({
                               (rights & NODE_RIGHTS_GROUP_READ) ? 'r' : '-',
                               (rights & NODE_RIGHTS_GROUP_WRITE) ? 'w' : '-',
                               (rights & NODE_RIGHTS_ALL_READ) ? 'r' : '-',
                               (rights & NODE_RIGHTS_ALL_WRITE) ? 'w' : '-'
                       });
}

#endif //CLOUD9_CLOUD_COMMON_H
