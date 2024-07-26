cmake_minimum_required(VERSION 3.24)

project (temp)

find_package (atsdk REQUIRED)

add_executable(main main.c)

target_link_libraries(main atsdk::atclient)

