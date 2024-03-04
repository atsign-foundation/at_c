cmake_minimum_required(VERSION 3.19)

project(
    repl
    VERSION 0.0.1
    LANGUAGES C
    HOMEPAGE_URL https://atsign.com
)

include(GNUInstallDirs)
include(FetchContent)

find_package(atclient REQUIRED CONFIG)
find_package (atchops CONFIG QUIET)
find_package (MbedTLS CONFIG QUIET)

message(STATUS "atclient was found")

add_executable(repl)

target_sources(repl PRIVATE src/main.c)
target_link_libraries(repl PRIVATE atclient::atclient)

# the target executable will be delivered to the packages/repl/bin directory, when building the `install` target.
install(
    TARGETS repl
    DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin
)
