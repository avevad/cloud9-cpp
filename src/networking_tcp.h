#ifndef CLOUD9_NETWORKING_TCP_H
#define CLOUD9_NETWORKING_TCP_H

#include "networking.h"

#define TCP_SOCKET_QUEUE_LENGTH 8

class TCPServer;

class TCPConnection final : public NetConnection {
private:
    friend TCPServer;

    int sock;

    explicit TCPConnection(int sock) : sock(sock) {}

public:
    TCPConnection() = delete;

    TCPConnection(const char *host, uint16_t port);

    size_t send(size_t n, const void *buffer) override;

    size_t read(size_t n, void *buffer) override;

    void close() override;

    bool is_valid() override;

    void flush() override;

    ~TCPConnection() override;
};


class TCPServer final : public NetServer {
private:
    int sock;
public:
    TCPServer() = delete;

    explicit TCPServer(int port);

    TCPConnection *accept() override;

    void destroy() override;

    bool is_valid() override;

    ~TCPServer() override;
};

#endif //CLOUD9_NETWORKING_TCP_H
