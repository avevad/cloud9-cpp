#include "networking_ssl.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdexcept>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <csignal>

#define SSL_SOCKET_QUEUE_LENGTH 16

inline std::runtime_error ssl_error(SSL *ssl, const char *pref, int status) {
    auto error = ERR_get_error();
    if (error) {
        return std::runtime_error(std::string(pref) + ": " + ERR_reason_error_string(error));
    } else if (status <= 0) {
        return std::runtime_error(std::string(pref) + ": " + std::to_string(SSL_get_error(ssl, status)));
    } else return std::runtime_error(pref + std::string(": unknown error"));
}

void init_networking_ssl() {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    signal(SIGPIPE, [](int) {});
}

void shutdown_networking_ssl() {
    ERR_free_strings();
    EVP_cleanup();
}

SSLConnection::SSLConnection(const char *host, int port) {
    addrinfo *server_info, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(host, std::to_string(port).c_str(), &hints, &server_info);
    if (status < 0) {
        throw std::runtime_error("failed to resolve host: " + std::string(gai_strerror(status)));
    }
    if (!server_info) {
        throw std::runtime_error("failed to resolve host");
    }
    sock = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(server_info);
        throw std::runtime_error("error opening client socket: " + std::string(strerror(errno)));
    }
    if (connect(sock, server_info->ai_addr, server_info->ai_addrlen)) {
        freeaddrinfo(server_info);
        throw std::runtime_error("error connecting to server: " + std::string(strerror(errno)));
    }
    freeaddrinfo(server_info);
    context = SSL_CTX_new(SSLv23_client_method());
    ssl = SSL_new(context);
    SSL_set_fd(ssl, sock);
    status = SSL_connect(ssl);
    if (status != 1) {
        ::close(sock);
        throw ssl_error(ssl, "failed to initiate SSL handshake with server", 1);
    }
}

size_t SSLConnection::send(size_t n, const void *buffer) {
    if (!is_valid()) throw std::runtime_error("not connected");
    int status = SSL_write(ssl, buffer, n);
    if (status <= 0) {
        auto error = ssl_error(ssl, "socket connection send error", status);
        close();
        throw error;
    } else return status;
}

size_t SSLConnection::read(size_t n, void *buffer) {
    if (!is_valid()) throw std::runtime_error("not connected");
    auto i = rand();
    int status = SSL_read(ssl, buffer, n);
    if (status <= 0) {
        auto error = ssl_error(ssl, "socket connection read error", status);
        close();
        throw error;
    } else return status;
}

void SSLConnection::close() {
    if (!is_valid()) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ssl = nullptr;
    ::shutdown(sock, SHUT_RDWR);
    ::close(sock);
    if (context) SSL_CTX_free(context);
}

SSLConnection::~SSLConnection() {
    if (is_valid()) {
        std::cout << "networking_ssl: warning: destructing valid connection" << std::endl;
        close();
    }
}

bool SSLConnection::is_valid() {
    return ssl != nullptr;
}

void SSLConnection::flush() {

}

SSLServer::SSLServer(int port, const char *cert, const char *key, pem_password_cb *password_cb, void *password_cb_ud)
        : cert(cert), key(key) {
    context = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_default_passwd_cb(context, password_cb);
    SSL_CTX_set_default_passwd_cb_userdata(context, password_cb_ud);
    if (SSL_CTX_use_certificate_file(context, cert, SSL_FILETYPE_PEM) <= 0) {
        throw std::invalid_argument("invalid certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(context, key, SSL_FILETYPE_PEM) <= 0) {
        throw std::invalid_argument("invalid private key");
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error(std::string("error opening server socket: ") + strerror(errno));
    }
    const int REUSE = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &REUSE, sizeof REUSE)) {
        throw std::runtime_error(std::string("failed to set reuse socket option: ") + strerror(errno));
    }
    sockaddr_in server_address;
    std::fill_n(reinterpret_cast<char *>(&server_address), sizeof server_address, '\0');
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, reinterpret_cast<const sockaddr *>(&server_address), sizeof server_address)) {
        throw std::runtime_error(std::string("error binding server socket: ") + strerror(errno));
    }
    if (listen(sock, SSL_SOCKET_QUEUE_LENGTH)) {
        throw std::runtime_error(std::string("error listening for connections: ") + strerror(errno));
    }
}

SSLConnection *SSLServer::accept() {
    int client = ::accept(sock, nullptr, nullptr);
    if (client < 0) throw std::runtime_error("accept failed: " + std::string(strerror(errno)));
    SSL *ssl = SSL_new(context);
    SSL_set_fd(ssl, client);
    auto status = SSL_accept(ssl);
    if (status != 1) {
        ::close(client);
        throw ssl_error(ssl, "failed to initiate SSL handshake with client", 1);
    }
    return new SSLConnection(ssl, client);
}

void SSLServer::destroy() {
    if (!is_valid()) return;
    ::shutdown(sock, SHUT_RDWR);
    ::close(sock);
    sock = -1;
    SSL_CTX_free(context);
    context = nullptr;
}

bool SSLServer::is_valid() {
    return sock >= 0;
}

SSLServer::~SSLServer() {
    if (is_valid()) {
        std::cout << "networking_ssl: warning: destructing valid server" << std::endl;
        destroy();
    }
}
