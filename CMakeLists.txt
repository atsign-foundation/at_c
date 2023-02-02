cmake_minimum_required(VERSION 3.13.4)

project(
  at_client
  VERSION 1.0.0
  DESCRIPTION "The at_client implemented in C"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

# mbedtls
add_subdirectory(deps/mbedtls)

# at_client
file(GLOB at_client_files lib/*.c)
add_library(at_client ${at_client_files})
target_include_directories(at_client PUBLIC include)
target_link_libraries(at_client PRIVATE mbedtls)

# tests
add_executable(tests test/test.c)
target_include_directories(tests PUBLIC include)
target_link_libraries(tests PRIVATE at_client)

