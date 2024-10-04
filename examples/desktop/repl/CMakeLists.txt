cmake_minimum_required(VERSION 3.19)

project(repl VERSION 0.0.1 LANGUAGES C HOMEPAGE_URL https://atsign.com)

include(FetchContent)

FetchContent_Declare(
  atclient
  SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atclient
)

FetchContent_Declare(
  argparse
  SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/3rdparty/argparse
)

FetchContent_MakeAvailable(atclient argparse)

add_executable(repl)

target_sources(repl PRIVATE src/main.c)
target_link_libraries(repl PRIVATE atclient argparse)
