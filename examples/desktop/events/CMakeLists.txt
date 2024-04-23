cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

find_package(atsdk REQUIRED CONFIG)

add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/notify.c)

target_link_libraries(exec PRIVATE atsdk::atclient)
