#ifndef CLOUD9_NETWORKING_H
#define CLOUD9_NETWORKING_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

class NetConnection {
public:
    virtual size_t send(size_t n, const void *buffer) = 0;

    virtual size_t read(size_t n, void *buffer) = 0;

    virtual void close() = 0;

    virtual bool is_valid() = 0;

    virtual void flush() = 0;

    virtual ~NetConnection() = default;
};

class NetServer {
public:
    virtual NetConnection *accept() = 0;

    virtual void destroy() = 0;

    virtual bool is_valid() = 0;

    virtual ~NetServer() = default;
};

template<class C>
class BufferedConnection : public NetConnection {
private:
    char *const buffer;
    const size_t buffer_size;
    size_t buffer_fullness;
    C *const connection;
public:
    template<typename ...A>
    explicit BufferedConnection(size_t buffer_size, A ...args) : connection(new C(args...)),
                                                                 buffer_size(buffer_size),
                                                                 buffer(new char[buffer_size]),
                                                                 buffer_fullness(0) {

    }

    BufferedConnection(size_t buffer_size, C *connection) : connection(connection),
                                                            buffer_size(buffer_size),
                                                            buffer(new char[buffer_size]),
                                                            buffer_fullness(0) {

    }

    size_t send(size_t n, const void *data) override {
        if (buffer_fullness + n > buffer_size) {
            flush();
            if (n > buffer_size) return connection->send(n, data);
        }
        memcpy(buffer + buffer_fullness, data, n);
        buffer_fullness += n;
        return n;
    }

    size_t read(size_t n, void *data) override {
        return connection->read(n, data);
    }

    void close() override {
        connection->close();
    }

    bool is_valid() override {
        return connection->is_valid();
    }

    void flush() override {
        connection->send(buffer_fullness, buffer);
        buffer_fullness = 0;
    }

    ~BufferedConnection() override {
        delete[] buffer;
        delete connection;
    }
};

#endif //CLOUD9_NETWORKING_H