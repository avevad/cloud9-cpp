cmake_minimum_required(VERSION 3.16)
project(cloud9)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(SRC_DIR src)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(Lua REQUIRED)
include_directories(${LUA_INCLUDE_DIR})

add_executable(cloud9 ${SRC_DIR}/launcher_client.cpp ${SRC_DIR}/networking_ssl.cpp ${SRC_DIR}/networking_tcp.cpp ${SRC_DIR}/cloud_client.cpp)
add_executable(cloud9d ${SRC_DIR}/launcher_server.cpp ${SRC_DIR}/networking_ssl.cpp ${SRC_DIR}/networking_tcp.cpp ${SRC_DIR}/cloud_server.cpp)

target_link_libraries(cloud9 ${OPENSSL_LIBRARIES})
target_link_libraries(cloud9d ${OPENSSL_LIBRARIES} ${LUA_LIBRARY})