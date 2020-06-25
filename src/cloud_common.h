#ifndef CLOUD9_CLOUD_COMMON_H
#define CLOUD9_CLOUD_COMMON_H

#include <string>
#include <cstring>
#include <algorithm>
#include "networking.h"

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

static uint32_t read_uint32(NetConnection *connection) {
    uint8_t buffer[4];
    read_exact(connection, 4, &buffer);
    uint32_t n = 0;
    for (uint8_t e : buffer) {
        n <<= uint32_t(8);
        n |= uint32_t(e);
    }
    return n;
}

static void send_uint64(NetConnection *connection, uint64_t n) {
    uint8_t buffer[8];
    for (int8_t i = 7; i >= 0; i--) {
        buffer[i] = n & uint64_t(0xFF);
        n >>= uint64_t(8);
    }
    send_exact(connection, 8, &buffer);
}

static uint64_t read_uint64(NetConnection *connection) {
    uint8_t buffer[8];
    read_exact(connection, 8, &buffer);
    uint64_t n = 0;
    for (uint8_t e : buffer) {
        n <<= uint64_t(8);
        n |= uint64_t(e);
    }
    return n;
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

static const char PATH_DIV = '/';
static const char CLOUD_PATH_DIV = '/';
static const char CLOUD_PATH_HOME = '~';
static const char CLOUD_PATH_NODE = '#';

static const uint64_t INIT_BODY_MAX_SIZE = 1024 * 8; // 8 KiB
static const uint16_t INIT_CMD_AUTH = 1;
static const uint16_t INIT_OK = 0;
static const uint16_t INIT_ERR_BODY_TOO_LARGE = 1;
static const uint16_t INIT_ERR_INVALID_CMD = 2;
static const uint16_t INIT_ERR_AUTH_FAILED = 3;
static const uint16_t INIT_ERR_MALFORMED_CMD = 4;

static const uint64_t REQUEST_BODY_MAX_SIZE = 1024 * 1024 * 8; // 8 MiB
static const uint16_t REQUEST_CMD_GET_HOME = 1;
static const uint16_t REQUEST_CMD_LIST_DIRECTORY = 2;
static const uint16_t REQUEST_CMD_GOODBYE = 3;
static const uint16_t REQUEST_CMD_GET_PARENT = 4;
static const uint16_t REQUEST_OK = 0;
static const uint16_t REQUEST_ERR_BODY_TOO_LARGE = 1;
static const uint16_t REQUEST_ERR_INVALID_CMD = 2;
static const uint16_t REQUEST_ERR_MALFORMED_CMD = 3;
static const uint16_t REQUEST_ERR_NOT_FOUND = 4;
static const uint16_t REQUEST_ERR_NOT_A_DIRECTORY = 5;
static const uint16_t REQUEST_ERR_FORBIDDEN = 6;

static const uint64_t USER_PASSWORD_SALT_LENGTH = 32;

static const uint64_t NODE_HEAD_OFFSET_TYPE = 0;
static const uint64_t NODE_HEAD_OFFSET_RIGHTS = 1;
static const uint64_t NODE_HEAD_OFFSET_OWNER_GROUP_SIZE = 2;
static const uint64_t NODE_HEAD_OFFSET_OWNER_GROUP = 3;

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
    else return "unknown init error (" + std::to_string(status) + ")";
}

static std::string request_status_string(uint16_t status) {
    if (status == REQUEST_OK) return "request OK";
    else if (status == REQUEST_ERR_BODY_TOO_LARGE) return "request body is too large";
    else if (status == REQUEST_ERR_INVALID_CMD) return "unknown request";
    else if (status == REQUEST_ERR_MALFORMED_CMD) return "malformed request";
    else if (status == REQUEST_ERR_NOT_FOUND) return "not found";
    else if (status == REQUEST_ERR_NOT_A_DIRECTORY) return "not a directory";
    else if (status == REQUEST_ERR_FORBIDDEN) return "forbidden";
    else return "unknown request error (" + std::to_string(status) + ")";
}

#define NODE_ID_LENGTH 16

typedef struct {
    uint8_t id[NODE_ID_LENGTH];
} Node;

static bool operator==(const Node &a, const Node &b) {
    return std::memcmp(&a, &b, sizeof(Node)) == 0;
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

#endif //CLOUD9_CLOUD_COMMON_H
