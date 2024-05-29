cmake_minimum_required(VERSION 3.19)
project(reconnection)

find_package(atsdk REQUIRED CONFIG)
message(STATUS "[atsdk] Found package!")

add_executable(reconnection ${CMAKE_CURRENT_LIST_DIR}/main.c)
target_link_libraries(reconnection PRIVATE atsdk::atclient)

install(TARGETS reconnection DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin)
