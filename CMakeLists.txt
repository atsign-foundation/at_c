cmake_minimum_required(VERSION 3.16)

option(BUILD_ESP_IDF "Build for ESP-IDF" OFF)
option(BUILD_ARDUINO "Build for Arduino" OFF)
option(BUILD_MBEDTLS "Build for mbedTLS" OFF)

if(BUILD_ESP_IDF) # build as an ESP-IDF components
  add_compile_definitions(BUILD_ESP_IDF)
  message(STATUS "BUILDING FOR ESP-IDF")
  set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/targets/esp32_espidf)
  set(COMPONENTS at_client at_chops esp32_espidf)
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

  FILE(GLOB_RECURSE at_client_sources ${CMAKE_SOURCE_DIR}/src/at_client/*.*)
  add_library(at_client ${at_client_sources})

  # setup at_chops library
  FILE(GLOB_RECURSE at_chops_sources ${CMAKE_SOURCE_DIR}/src/at_chops/*.*)
  add_library(at_chops ${at_chops_sources})

  set_target_properties(at_client PROPERTIES LINKER_LANGUAGE C)
  set(CMAKE_C_STANDARD 99)
  target_compile_features(at_client PRIVATE c_std_99)

  target_include_directories(at_chops PUBLIC ${CMAKE_SOURCE_DIR}/include)
  target_include_directories(at_chops PUBLIC ${CMAKE_SOURCE_DIR}/include/at_chops)
  target_include_directories(at_client PUBLIC ${CMAKE_SOURCE_DIR}/include)
  target_include_directories(at_client PUBLIC ${CMAKE_SOURCE_DIR}/include/at_client)

  # link libraries
  if(BUILD_MBEDTLS)
    target_link_libraries(at_chops PRIVATE mbedtls)
    target_link_libraries(at_chops PRIVATE mbedx509)
    target_link_libraries(at_chops PRIVATE mbedcrypto)
  endif()

  if(BUILD_ARDUINO)
    target_link_arduino_libraries(at_chops PRIVATE core)
  endif()

  target_link_libraries(at_client PRIVATE at_chops)

  # tests
  enable_testing()

  add_executable(test_base64 test/test_base64.c)
  target_link_libraries(test_base64 PRIVATE at_client)
  add_test(
    NAME BASE64
    COMMAND $<TARGET_FILE:test_base64>)

  add_executable(test_aes_ctr test/test_aes_ctr.c)
  target_link_libraries(test_aes_ctr PRIVATE at_client)
  add_test(
    NAME AES_CTR
    COMMAND $<TARGET_FILE:test_aes_ctr>)

  add_executable(test_rsapublicpopulate test/test_rsapublicpopulate.c)
  target_link_libraries(test_rsapublicpopulate PRIVATE at_client)
  add_test(
    NAME RSA_PUBLICPOPULATE
    COMMAND $<TARGET_FILE:test_rsapublicpopulate>)

  add_executable(test_rsaprivatepopulate test/test_rsaprivatepopulate.c)
  target_link_libraries(test_rsaprivatepopulate PRIVATE at_client)
  add_test(
    NAME RSA_PRIVATEPOPULATE
    COMMAND $<TARGET_FILE:test_rsaprivatepopulate>)

  add_executable(test_rsasign test/test_rsasign.c)
  target_link_libraries(test_rsasign PRIVATE at_client)
  add_test(
    NAME RSA_SIGN
    COMMAND $<TARGET_FILE:test_rsasign>)

  add_executable(test_rsaencrypt test/test_rsaencrypt.c)
  target_link_libraries(test_rsaencrypt PRIVATE at_client)
  add_test(
    NAME RSA_ENCRYPT
    COMMAND $<TARGET_FILE:test_rsaencrypt>)

#   add_executable(test_main test/test_main.c)
#   target_link_libraries(test_main PRIVATE at_client)
#   add_test(
#     NAME MAIN
#     COMMAND $<TARGET_FILE:test_main>)

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



