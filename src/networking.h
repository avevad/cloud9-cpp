#ifndef CLOUD9_NETWORKING_H
#define CLOUD9_NETWORKING_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class NetConnection {
public:
    virtual size_t send(size_t n, const void *buffer) = 0;

    virtual size_t read(size_t n, void *buffer) = 0;

    virtual void close() = 0;

    virtual bool is_valid() = 0;

    virtual ~NetConnection() = default;
};

class NetServer {
public:
    virtual NetConnection *accept() = 0;

    virtual void destroy() = 0;

    virtual bool is_valid() = 0;

    virtual ~NetServer() = default;
};


#endif //CLOUD9_NETWORKING_H