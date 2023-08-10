cmake_minimum_required(VERSION 3.19)

project(
    repl
    VERSION 0.0.1
    LANGUAGES C
    HOMEPAGE_URL https://atsign.com
)

find_package(atchops REQUIRED CONFIG) # install via tools/install-atclient.sh
find_package(atclient REQUIRED CONFIG) # install via tools/install-atclient.sh

message(STATUS "atclient was found")

add_executable(repl)

target_sources(repl PRIVATE src/main.c)

target_link_libraries(repl PRIVATE atclient::atclient)

install(
    TARGETS repl
    DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin
)
