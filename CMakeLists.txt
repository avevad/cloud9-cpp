cmake_minimum_required(VERSION 3.0)
project(cloud9)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++17")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lstdc++fs")
set(SRC_DIR src)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(Lua REQUIRED)
include_directories(${LUA_INCLUDE_DIR})

add_library(cloud9_common ${SRC_DIR}/networking_ssl.cpp ${SRC_DIR}/networking_tcp.cpp)
add_library(cloud9_client ${SRC_DIR}/cloud_client.cpp)
add_library(cloud9_server ${SRC_DIR}/cloud_server.cpp)

add_executable(cloud9 ${SRC_DIR}/launcher_client.cpp)
add_executable(cloud9d ${SRC_DIR}/launcher_server.cpp)
add_executable(tester ${SRC_DIR}/test.cpp)

target_link_libraries(cloud9_common ${OPENSSL_LIBRARIES})
target_link_libraries(cloud9_server ${LUA_LIBRARY})

target_link_libraries(cloud9 cloud9_common cloud9_client)
target_link_libraries(cloud9d cloud9_common cloud9_server)
target_link_libraries(tester cloud9_common cloud9_client cloud9_server)

install(TARGETS cloud9 DESTINATION bin)
install(TARGETS cloud9d DESTINATION sbin)

enable_testing()

list(APPEND TESTS make_node homes dirs groups tokens)

foreach (TEST IN LISTS TESTS)
    add_test(NAME tester_${TEST}_test COMMAND ./tester ${TEST})
endforeach ()