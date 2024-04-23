cmake_minimum_required(VERSION 3.19)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)
include(GNUInstallDirs)

project(sample_cmake_project)

find_package(atSDK REQUIRED CONFIG)
message(STATUS "[atSDK] Found package!")

add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/main.c)
target_link_libraries(exec PRIVATE atSDK::atclient)
