cmake_minimum_required(VERSION 3.19)

project(temp)

find_package(atclient REQUIRED CONFIG)
find_package(atchops QUIET)
find_package(MbedTLS QUIET)

message(STATUS "Found atclient: ${atclient_FOUND}")

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/main.c)

target_link_libraries(main PRIVATE atclient::atclient)
