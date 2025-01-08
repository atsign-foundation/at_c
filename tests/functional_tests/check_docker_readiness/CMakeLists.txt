cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

project(check_docker_readiness)

# Import atclient
if(NOT TARGET atclient)
  set(atclient_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atclient)
  include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/atclient.cmake)
endif()

# set(CHECK_DOCKER_READINESS_INCLUDE_DIRS
#   ${CMAKE_CURRENT_LIST_DIR}/include
# )

set(
  CHECK_DOCKER_READINESS_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/main.c
)


add_executable(check_docker_readiness ${CHECK_DOCKER_READINESS_SOURCES})

# target_include_directories(
#   check_docker_readiness
#   PUBLIC ${CHECK_DOCKER_READINESS_INCLUDE_DIRS}
# )

target_link_libraries(check_docker_readiness PUBLIC atclient)
