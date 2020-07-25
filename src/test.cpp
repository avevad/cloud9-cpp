#include <iostream>
#include "networking_tcp.h"
#include "cloud_server.h"
#include "cloud_client.h"

bool sample_test(int, char **) {
    return true;
}

int main(int argc, char **argv) {
    std::map<std::string, std::function<bool(int, char **)>> tests;
    tests["sample_test"] = sample_test;
    if (argc == 0 || !tests.contains(argv[1])) {
        std::cerr << "invalid test name" << std::endl;
        return 1;
    } else return !tests[argv[1]](argc - 1, argv + 2);
}