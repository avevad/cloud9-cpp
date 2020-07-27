#ifndef CLOUD9_SERVER_CONFIG_H
#define CLOUD9_SERVER_CONFIG_H

#include "cloud_server.h"
#include <filesystem>

extern "C" {
#include "lua.h"
};

struct LauncherConfig : public CloudConfig {
    uint16_t server_port;
};

struct ConfigLoaderData {
    std::istream *stream;
    char *prev;

    explicit ConfigLoaderData(std::istream *stream) : stream(stream), prev(nullptr) {}
};


static const char CONFIG_DIV = '.';

void get_config_option(lua_State *state, const std::string &path, const std::string &table_path) {
    auto index = lua_gettop(state);
    if (!lua_istable(state, index)) {
        lua_close(state);
        throw std::invalid_argument("invalid config: " + table_path + " must be a table");
    }
    std::string name = path.substr(0, path.find(CONFIG_DIV));
    lua_pushstring(state, name.c_str());
    lua_gettable(state, index);
    lua_copy(state, lua_gettop(state), index);
    lua_pop(state, 1);
    if (path.find(CONFIG_DIV) != std::string::npos) {
        get_config_option(state, path.substr(path.find(CONFIG_DIV) + 1), table_path + CONFIG_DIV + name);
    }
}

void global_get_config_option(lua_State *state, const std::string &path) {
    std::string global_name = path.substr(0, path.find(CONFIG_DIV));
    lua_getglobal(state, global_name.c_str());
    if (path.find(CONFIG_DIV) != std::string::npos) {
        get_config_option(state, path.substr(path.find(CONFIG_DIV) + 1), global_name);
    }
}

std::string global_get_config_string(lua_State *state, const std::string &path, const std::string *def = nullptr) {
    global_get_config_option(state, path);
    if (!lua_isstring(state, lua_gettop(state))) {
        if (def && lua_isnil(state, lua_gettop(state))) {
            lua_pop(state, 1);
            return *def;
        }
        lua_close(state);
        throw std::invalid_argument("invalid config: " + path + " must be a string");
    }
    std::string res = lua_tostring(state, lua_gettop(state));
    lua_pop(state, 1);
    return res;
}

LUA_INTEGER global_get_config_integer(lua_State *state, const std::string &path, const LUA_INTEGER *def = nullptr) {
    global_get_config_option(state, path);
    if (!lua_isinteger(state, lua_gettop(state))) {
        if (def && lua_isnil(state, lua_gettop(state))) {
            lua_pop(state, 1);
            return *def;
        }
        lua_close(state);
        throw std::invalid_argument("invalid config: " + path + " must be an integer");
    }
    LUA_INTEGER res = lua_tointeger(state, lua_gettop(state));
    lua_pop(state, 1);
    return res;
}


static const size_t CONFIG_LOADER_BUFFER_SIZE = 4096;
static const char *CONFIG_FILE = "config.lua";
static const char *CONFIG_CHUNK_NAME = "=config";
static const char *CONFIG_OPTION_USERS_DIRECTORY = "cloud.users_directory";
static const char *CONFIG_OPTION_NODES_HEAD_DIRECTORY = "cloud.nodes_head_directory";
static const char *CONFIG_OPTION_NODES_DATA_DIRECTORY = "cloud.nodes_data_directory";
static const char *CONFIG_OPTION_ACCESS_LOG = "cloud.access_log";
static const std::string CONFIG_DEFAULT_ACCESS_LOG = "";

static const char *CONFIG_OPTION_LAUNCHER = "launcher";
static const char *CONFIG_OPTION_SERVER_PORT = "launcher.server_port";
static const LUA_INTEGER CONFIG_DEFAULT_SERVER_PORT = CLOUD_DEFAULT_PORT;

void load_config(LauncherConfig &config) {
    if (!std::filesystem::is_regular_file(CONFIG_FILE)) throw std::invalid_argument("nonexistent config file");
    std::ifstream config_file_stream(CONFIG_FILE);
    std::string config_string((std::istreambuf_iterator<char>(config_file_stream)), std::istreambuf_iterator<char>());
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

    config.users_directory = global_get_config_string(state, CONFIG_OPTION_USERS_DIRECTORY);
    config.nodes_head_directory = global_get_config_string(state, CONFIG_OPTION_NODES_HEAD_DIRECTORY);
    config.nodes_data_directory = global_get_config_string(state, CONFIG_OPTION_NODES_DATA_DIRECTORY);
    config.access_log = global_get_config_string(state, CONFIG_OPTION_ACCESS_LOG, &CONFIG_DEFAULT_ACCESS_LOG);

    global_get_config_option(state, CONFIG_OPTION_LAUNCHER);
    if (lua_isnil(state, lua_gettop(state))) {
        lua_newtable(state);
        lua_setglobal(state, CONFIG_OPTION_LAUNCHER);
        lua_pop(state, 1);
    }

    config.server_port = global_get_config_integer(state, CONFIG_OPTION_SERVER_PORT, &CONFIG_DEFAULT_SERVER_PORT);

    lua_close(state);
}

#endif //CLOUD9_SERVER_CONFIG_H
