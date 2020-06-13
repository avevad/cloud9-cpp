#ifndef CLOUD9_NETWORKING_SSL_H
#define CLOUD9_NETWORKING_SSL_H

#include "networking.h"

void init_networking_ssl();

void shutdown_networking_ssl();

class SSLServer;

class SSLConnection final : public NetConnection {
private:
    SSL *ssl;
    int sock;
    SSL_CTX *context;

    SSLConnection(SSL *ssl, int sock) : ssl(ssl), sock(sock), context(nullptr) {}

    friend SSLServer;
public:
    SSLConnection(const char *host, int port);

    size_t send(size_t n, const void *buffer) override;

    size_t read(size_t n, void *buffer) override;

    void close() override;

    bool is_valid() override;

    ~SSLConnection() override;
};

class SSLServer final : public NetServer {
private:
    int sock;
    SSL_CTX *context;
    const char *const cert, *const key;
public:
    SSLServer() = delete;

    SSLServer(int port, const char *cert, const char *key, pem_password_cb *password_cb, void *password_cb_ud);

    SSLConnection *accept() override;

    void destroy() override;

    bool is_valid() override;

    ~SSLServer() override;
};

#endif //CLOUD9_NETWORKING_SSL_H
