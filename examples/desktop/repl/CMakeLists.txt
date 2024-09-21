cmake_minimum_required(VERSION 3.19)

project(repl)

include(FetchContent)

FetchContent_Declare(
    atsdk
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
)

FetchContent_MakeAvailable(atsdk)

add_executable(repl ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(repl PRIVATE atclient)

install(TARGETS repl DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin)
