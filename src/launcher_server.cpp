#include <stdexcept>
#include <iostream>
#include <cstring>
#include <csignal>
#include <filesystem>
#include <fstream>

#include "lua5.3/lua.h"

#include "networking_ssl.h"
#include "networking_tcp.h"
#include "cloud_server.h"

void load_config(const char *, CloudConfig &);

int main(int argc, const char **argv) {
    signal(SIGPIPE, [](int) {});
    if (argc != 3) {
        std::cerr << "invalid number of arguments" << std::endl;
        return 1;
    }
    CloudConfig config;
    try {
        load_config(argv[1], config);
    } catch (std::exception &exception) {
        std::cerr << "failed to load configuration file: " << exception.what() << std::endl;
        return 1;
    }
    NetServer *net = new TCPServer(atoi(argv[2]));
    auto *server = new CloudServer(net, config);
    std::string s;
    std::getline(std::cin, s);
    delete server;
}

static const size_t CONFIG_LOADER_BUFFER_SIZE = 4096;
static const char *CONFIG_CHUNK_NAME = "config";
static const char *CONFIG_OPTION_USERS_DIRECTORY = "users_directory";
static const char *CONFIG_OPTION_NODES_HEAD_DIRECTORY = "nodes_head_directory";
static const char *CONFIG_OPTION_NODES_DATA_DIRECTORY = "nodes_data_directory";

struct ConfigLoaderData {
    std::istream *stream;
    char *prev;

    explicit ConfigLoaderData(std::istream *stream) : stream(stream), prev(nullptr) {}
};

void load_config(const char *config_file, CloudConfig &config) {
    if (!std::filesystem::is_regular_file(config_file)) throw std::invalid_argument("nonexistent config file");
    std::ifstream config_file_stream(config_file);
    std::string config_string((std::istreambuf_iterator<char>(config_file_stream)), std::istreambuf_iterator<char>());
    config_string = "return " + config_string;
    lua_State *state = lua_newstate([](void *data, void *ptr, size_t old_size, size_t new_size) -> void * {
        if (new_size == 0) {
            free(ptr);
            return nullptr;
        } else return realloc(ptr, new_size);
    }, nullptr);
    std::istringstream config_stream(config_string);
    ConfigLoaderData loader_data(&config_stream);
    int status = lua_load(state, [](lua_State *, void *data, size_t *size) -> const char * {
        auto *loader_data = static_cast<ConfigLoaderData *>(data);
        delete[] loader_data->prev;
        loader_data->prev = new char[CONFIG_LOADER_BUFFER_SIZE + 1];
        *size = loader_data->stream->readsome(loader_data->prev, CONFIG_LOADER_BUFFER_SIZE);
        loader_data->prev[*size] = '\0';
        return loader_data->prev;
    }, &loader_data, CONFIG_CHUNK_NAME, "t");
    delete[] loader_data.prev;
    if (status != LUA_OK) {
        std::string what = lua_isstring(state, lua_gettop(state)) ?
                           std::string("invalid config: ") + lua_tostring(state, lua_gettop(state)) :
                           "invalid config: unknown error";
        lua_close(state);
        throw std::invalid_argument(what);
    }
    status = lua_pcall(state, 0, 1, 0);
    if (status != LUA_OK) {
        std::string what = lua_isstring(state, lua_gettop(state)) ?
                           std::string("invalid config: ") + lua_tostring(state, lua_gettop(state)) :
                           "invalid config: unknown error";
        lua_close(state);
        throw std::invalid_argument(what);
    }
    if (!lua_istable(state, lua_gettop(state))) {
        lua_close(state);
        throw std::invalid_argument("config must be a table");
    }
    auto config_table = lua_gettop(state);

#define NO_OPTION(opt_name) {lua_close(state); throw std::invalid_argument("necessary option '" + std::string(opt_name) + "' is absent or invalid type");}


    lua_pushstring(state, CONFIG_OPTION_USERS_DIRECTORY);
    lua_gettable(state, config_table);
    if (!lua_isstring(state, lua_gettop(state))) NO_OPTION(CONFIG_OPTION_USERS_DIRECTORY);
    config.users_directory = lua_tostring(state, lua_gettop(state));
    lua_pop(state, 1);

    lua_pushstring(state, CONFIG_OPTION_NODES_HEAD_DIRECTORY);
    lua_gettable(state, config_table);
    if (!lua_isstring(state, lua_gettop(state))) NO_OPTION(CONFIG_OPTION_NODES_HEAD_DIRECTORY);
    config.nodes_head_directory = lua_tostring(state, lua_gettop(state));
    lua_pop(state, 1);

    lua_pushstring(state, CONFIG_OPTION_NODES_DATA_DIRECTORY);
    lua_gettable(state, config_table);
    if (!lua_isstring(state, lua_gettop(state))) NO_OPTION(CONFIG_OPTION_NODES_DATA_DIRECTORY);
    config.nodes_data_directory = lua_tostring(state, lua_gettop(state));
    lua_pop(state, 1);

#undef NO_OPTION

    lua_close(state);
}