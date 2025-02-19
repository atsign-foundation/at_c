cmake_minimum_required(VERSION 3.24)

project(playground)

include(FetchContent)

FetchContent_Declare(
  atclient
  SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atclient
)

FetchContent_MakeAvailable(atclient)

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/main.c)

target_link_libraries(main PRIVATE atclient)