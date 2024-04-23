cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

find_package(atSDK REQUIRED CONFIG)
find_package(cjson REQUIRED)

add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/notify.c)

target_link_libraries(exec PRIVATE atSDK::atclient atSDK::atlogger)
