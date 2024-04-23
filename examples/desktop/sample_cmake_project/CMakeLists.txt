cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

find_package(atSDK REQUIRED CONFIG)

message(STATUS "Found atclient!")

add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/main.c)

target_link_libraries(exec PRIVATE atSDK::atclient)
