#ifndef CLOUD9_CLOUD_COMMON_H
#define CLOUD9_CLOUD_COMMON_H

#include <string>
#include <cstring>
#include "networking.h"

static void read_exact(NetConnection *connection, size_t size, void *buffer) {
    size_t read = 0;
    while (read < size) read += connection->read(size - read, (char *) buffer + read);
}

static void send_exact(NetConnection *connection, size_t size, const void *buffer) {
    size_t sent = 0;
    while (sent < size) sent += connection->send(size - sent, (const char *) buffer + sent);
}

template<typename T>
static T read_any(NetConnection *connection) {
    T result;
    read_exact(connection, sizeof(T), &result);
    return result;
}

template<typename T>
static void send_any(NetConnection *connection, T n) {
    send_exact(connection, sizeof(T), &n);
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

static const int INIT_BODY_MAX_SIZE = 1024 * 8; // 8 KiB
static const int INIT_CMD_AUTH = 1;
static const int INIT_OK = 0;
static const int INIT_ERR_BODY_TOO_LARGE = 1;
static const int INIT_ERR_INVALID_CMD = 2;
static const int INIT_ERR_AUTH_FAILED = 3;
static const int INIT_ERR_MALFORMED_CMD = 4;

static const int REQUEST_BODY_MAX_SIZE = 1024 * 1024 * 8; // 8 MiB
static const int REQUEST_CMD_GET_HOME = 1;
static const int REQUEST_CMD_LIST_DIRECTORY = 2;
static const int REQUEST_CMD_GOODBYE = 3;
static const int REQUEST_OK = 0;
static const int REQUEST_ERR_BODY_TOO_LARGE = 1;
static const int REQUEST_ERR_INVALID_CMD = 2;
static const int REQUEST_ERR_MALFORMED_CMD = 3;
static const int REQUEST_ERR_NOT_FOUND = 4;
static const int REQUEST_ERR_NOT_A_DIRECTORY = 5;

static const size_t USER_PASSWORD_SALT_LENGTH = 32;

static const size_t NODE_HEAD_TYPE_OFFSET = 0;

static const int NODE_TYPE_FILE = 0;
static const int NODE_TYPE_DIRECTORY = 1;

static std::string init_status_string(int status) {
    if(status == INIT_OK) return "init OK";
    else if(status == INIT_ERR_BODY_TOO_LARGE) return "init body is too large";
    else if(status == INIT_ERR_INVALID_CMD) return "unknown init command";
    else if(status == INIT_ERR_AUTH_FAILED) return "access denied";
    else if(status == INIT_ERR_MALFORMED_CMD) return "malformed init command";
    else return "unknown init error (" + std::to_string(status) + ")";
}

static std::string request_status_string(int status) {
    if(status == REQUEST_OK) return "request OK";
    else if(status == REQUEST_ERR_BODY_TOO_LARGE) return "request body is too large";
    else if(status == REQUEST_ERR_INVALID_CMD) return "unknown request";
    else if(status == REQUEST_ERR_MALFORMED_CMD) return "malformed request";
    else if(status == REQUEST_ERR_NOT_FOUND) return "not found";
    else if(status == REQUEST_ERR_NOT_A_DIRECTORY) return "not a directory";
    else return "unknown request error (" + std::to_string(status) + ")";
}

#define NODE_ID_LENGTH 16

typedef struct {
    unsigned char id[NODE_ID_LENGTH];
} Node;

static std::string node2string(Node node) {
    std::string s(NODE_ID_LENGTH * 2, 0);
    for (size_t i = 0; i < NODE_ID_LENGTH; i++) {
        unsigned char d1 = node.id[i] / 0x10u;
        unsigned char d2 = node.id[i] & 0xFu;
        s[i * 2] = d1 < 10 ? ('0' + d1) : ('a' - 10 + d1);
        s[i * 2 + 1] = d2 < 10 ? ('0' + d2) : ('a' - 10 + d2);
    }
    return s;
}

#endif //CLOUD9_CLOUD_COMMON_H
