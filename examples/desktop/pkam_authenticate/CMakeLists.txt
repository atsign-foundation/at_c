cmake_minimum_required(VERSION 3.19)

project(pkam_authenticate LANGUAGES C VERSION 0.1.0)

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

find_package(atsdk CONFIG REQUIRED)

target_link_libraries(main PRIVATE atsdk::atclient)

