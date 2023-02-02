cmake_minimum_required(VERSION 3.16.0)

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

target_compile_features(at_client PUBLIC c_std_99)
target_include_directories(at_client PUBLIC include)
target_link_libraries(at_client PRIVATE mbedtls)

# tests
add_executable(tests test/test.c)

target_include_directories(tests PUBLIC include)
target_link_libraries(tests PRIVATE at_client)

target_compile_options(at_client # https://vladiant.github.io/blog/2021/08/14/cpp-compiler-flags
  PRIVATE -Wall -Wextra -Wuninitialized -Wpedantic -Werror -Wshadow -Wmissing-include-dirs -Wundef -Winvalid-pch # Essentials
  PRIVATE -Winit-self -Wswitch-enum -Wswitch-default -Wformat=2 -Wformat-nonliteral -Wformat-security -Wformat-y2k # Control flow
  PRIVATE -Wdouble-promotion -Wfloat-equal -Wpointer-arith # Arithmetic
  PRIVATE -Wstrict-overflow=5 -Wcast-qual -Wcast-align -Wconversion -Wpacked # Casting
  PRIVATE -Wstrict-aliasing -fstrict-aliasing -Wredundant-decls -Wmissing-declarations -Wmissing-field-initializers # Sanitizing
  PRIVATE -Wwrite-strings -Wstack-protector -fstack-protector -Wpadded -Winline -Wdisabled-optimization # Security
  PRIVATE -Waggregate-return -Wbad-function-cast -Wc++-compat # C specific
)