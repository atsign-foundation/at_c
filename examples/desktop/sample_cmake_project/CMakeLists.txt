cmake_minimum_required(VERSION 3.19)
project(sample_cmake_project)

find_package(atsdk REQUIRED CONFIG)
message(STATUS "[atsdk] Found package!")

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/main.c)
target_link_libraries(main PRIVATE atsdk::atclient)
