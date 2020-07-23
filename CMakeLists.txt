cmake_minimum_required(VERSION 3.10)
project(cloud9)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lstdc++fs")
set(SRC_DIR src)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(Lua REQUIRED)
include_directories(${LUA_INCLUDE_DIR})

add_library(cloud9_common ${SRC_DIR}/networking_ssl.cpp ${SRC_DIR}/networking_tcp.cpp)

add_executable(cloud9 ${SRC_DIR}/launcher_client.cpp ${SRC_DIR}/cloud_client.cpp)
add_executable(cloud9d ${SRC_DIR}/launcher_server.cpp ${SRC_DIR}/cloud_server.cpp)

target_link_libraries(cloud9 ${OPENSSL_LIBRARIES} cloud9_common)
target_link_libraries(cloud9d ${OPENSSL_LIBRARIES} ${LUA_LIBRARY} cloud9_common)

install(TARGETS cloud9 DESTINATION bin)
install(TARGETS cloud9d DESTINATION sbin)
