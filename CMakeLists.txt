cmake_minimum_required(VERSION 3.16)

option(BUILD_ESP_IDF "Build for ESP-IDF" OFF)

if(BUILD_ESP_IDF) # build as an ESP-IDF components
  message(STATUS "BUILDING FOR ESP-IDF")
  set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/targets/esp32_espidf)
  set(COMPONENTS at_client esp32_espidf)
  include($ENV{IDF_PATH}/tools/cmake/project.cmake)
endif()

project(
  at_client
  VERSION 1.0.0
  DESCRIPTION "The at_client implemented in C"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

if(NOT BUILD_ESP_IDF) # build for other platforms
  # library files
  add_subdirectory(deps/mbedtls)

  FILE(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/src/at_client/*.*)
  add_library(at_client ${sources})

  target_compile_features(at_client PUBLIC c_std_99)
  target_include_directories(at_client PUBLIC include)
  target_link_libraries(at_client PRIVATE mbedtls)

  # tests
  add_executable(tests test/test.c)

  target_include_directories(tests PUBLIC include)
  target_link_libraries(tests PRIVATE at_client)

  # compiler flags
  target_compile_options(at_client # https://vladiant.github.io/blog/2021/08/14/cpp-compiler-flags
    PRIVATE -Wall -Wextra -Wuninitialized -Wpedantic -Werror -Wshadow -Wmissing-include-dirs -Wundef -Winvalid-pch # Essentials
    PRIVATE -Winit-self -Wswitch-enum -Wswitch-default -Wformat=2 -Wformat-nonliteral -Wformat-security -Wformat-y2k # Control flow
    PRIVATE -Wdouble-promotion -Wfloat-equal -Wpointer-arith # Arithmetic
    PRIVATE -Wstrict-overflow=5 -Wcast-qual -Wcast-align -Wconversion -Wpacked # Casting
    PRIVATE -Wstrict-aliasing -fstrict-aliasing -Wredundant-decls -Wmissing-declarations -Wmissing-field-initializers # Sanitizing
    PRIVATE -Wwrite-strings -Wstack-protector -fstack-protector -Wpadded -Winline -Wdisabled-optimization # Security
    PRIVATE -Waggregate-return -Wbad-function-cast -Wc++-compat # C specific
  )

endif()



