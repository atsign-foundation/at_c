cmake_minimum_required(VERSION 3.16)

option(BUILD_ESP_IDF "Build for ESP-IDF" OFF)
option(BUILD_ARDUINO "Build for Arduino" OFF)
option(BUILD_MBEDTLS "Build for mbedTLS" OFF)

if(BUILD_ESP_IDF) # build as an ESP-IDF components
  add_compile_definitions(BUILD_ESP_IDF)
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
  LANGUAGES CXX
)

if(NOT BUILD_ESP_IDF) # build for other platforms

  # build libraries

  if(BUILD_MBEDTLS)
    add_compile_definitions(BUILD_MBEDTLS)
    message(STATUS "BUILDING FOR MBEDTLS")
    add_subdirectory(deps/mbedtls)
  endif()

  if(BUILD_ARDUINO)
    add_compile_definitions(BUILD_ARDUINO)
    message(STATUS "BUILDING FOR ARDUINO")
    include(${CMAKE_CURRENT_SOURCE_DIR}/deps/Arduino-CMake-Toolchain/Arduino-toolchain.cmake)
  endif()

  # setup at_client library

  FILE(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/src/at_client/*.*)
  add_library(at_client ${sources})

  set_target_properties(at_client PROPERTIES LINKER_LANGUAGE CXX)
  set(CMAKE_CXX_STANDARD 17)
  target_compile_features(at_client PRIVATE cxx_std_17)
  target_include_directories(at_client PUBLIC include)

  # link libraries

  if(BUILD_MBEDTLS)
    target_link_libraries(at_client PRIVATE mbedtls)
    target_link_libraries(at_client PRIVATE mbedx509)
    target_link_libraries(at_client PRIVATE mbedcrypto)
  endif()

  if(BUILD_ARDUINO)
    target_link_arduino_libraries(at_client PRIVATE core)
  endif()

  # tests
  # add_executable(tests test/test.c)

  # target_include_directories(tests PUBLIC include)
  # target_link_libraries(tests PRIVATE at_client)

  # compiler flags
  target_compile_options(at_client # https://vladiant.github.io/blog/2021/08/14/cpp-compiler-flags
    PRIVATE -Wall -Wextra -Wuninitialized -Wpedantic -Wshadow -Wmissing-include-dirs -Wundef -Winvalid-pch # Essentials
    PRIVATE -Winit-self -Wswitch-enum -Wswitch-default -Wformat=2 -Wformat-nonliteral -Wformat-security -Wformat-y2k # Control flow
    PRIVATE -Wdouble-promotion -Wfloat-equal -Wpointer-arith # Arithmetic
    PRIVATE -Wstrict-overflow=5 -Wcast-qual -Wcast-align -Wconversion -Wpacked # Casting
    PRIVATE -Wstrict-aliasing -fstrict-aliasing -Wredundant-decls -Wmissing-declarations -Wmissing-field-initializers # Sanitizing
    PRIVATE -Wwrite-strings -Wstack-protector -fstack-protector -Wpadded -Winline -Wdisabled-optimization # Security
    PRIVATE -Waggregate-return -Wbad-function-cast -Wc++-compat # C specific
  )

endif()



