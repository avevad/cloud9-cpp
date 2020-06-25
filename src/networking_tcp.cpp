#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <iostream>
#include "networking_tcp.h"

TCPConnection::TCPConnection(const char *host, int port) {
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
}

size_t TCPConnection::send(size_t n, const void *buffer) {
    if (!is_valid()) throw std::runtime_error("connection is closed");
    ssize_t sent = ::send(sock, buffer, n, 0);
    if (sent == -1) {
        close();
        throw std::runtime_error(strerror(errno));
    }
    return sent;
}

size_t TCPConnection::read(size_t n, void *buffer) {
    if (!is_valid()) throw std::runtime_error("connection is closed");
    ssize_t read = ::recv(sock, buffer, n, 0);
    if (read == -1) {
        close();
        throw std::runtime_error(strerror(errno));
    }
    if (read == 0) {
        close();
        throw std::runtime_error("connection reset by peer");
    }
    return read;
}

void TCPConnection::close() {
    if (sock == -1) return;
    shutdown(sock, SHUT_RDWR);
    ::close(sock);
    sock = -1;
}

bool TCPConnection::is_valid() {
    return sock != -1;
}

TCPConnection::~TCPConnection() {
    if (is_valid()) {
        std::cout << "networking_tcp: warning: destructing valid connection" << std::endl;
        close();
    }
}

TCPServer::TCPServer(int port) {
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
    if (listen(sock, TCP_SOCKET_QUEUE_LENGTH)) {
        throw std::runtime_error(std::string("error listening for connections: ") + strerror(errno));
    }
}

TCPConnection *TCPServer::accept() {
    if (!is_valid()) throw std::runtime_error("server is destroyed");
    int client = ::accept(sock, nullptr, nullptr);
    if (client == -1) throw std::runtime_error(strerror(errno));
    return new TCPConnection(client);
}

void TCPServer::destroy() {
    if (sock == -1) return;
    shutdown(sock, SHUT_RDWR);
    ::close(sock);
    sock = -1;
}

bool TCPServer::is_valid() {
    return sock != -1;
}

TCPServer::~TCPServer() {
    if (is_valid()) {
        std::cout << "networking_tcp: warning: destructing valid server" << std::endl;
        destroy();
    }
}
