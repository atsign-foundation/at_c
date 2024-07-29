cmake_minimum_required(VERSION 3.24)

project(temp)

find_package(atsdk REQUIRED)

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/main.c)
target_link_libraries(main atsdk::atclient)

install(TARGETS main DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin)
