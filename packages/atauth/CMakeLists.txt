# Configurable options
option(ATAUTH_BUILD_TESTS "Build tests for atauth" OFF)
option(ATAUTH_BUILD_EXECUTABLES "Build executables in atauth" ON)

# Set include directory and file sources
set(ATAUTH_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
  ATAUTH_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/send_enroll_request.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atactivate_arg_parser.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atactivate.c
  ${CMAKE_CURRENT_LIST_DIR}/src/auth_cli.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atauth_build_atkeys_file_path.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atauth_fetch_home_dir.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_operation.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_status.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_namespace.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_params.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_command_builder.c
)

# Project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

## not adding the esp target yet

project(
  atauth
  VERSION 0.0.1
  DESCRIPTION "Atsign technology authentication library"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME atauth
    PACKAGE_DESCRIPTION "Atsign technology authentication library"
    PACKAGE_VERSION 0.0.1
    INCLUDE_DIR ${ATAUTH_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATAUTH_SOURCES}
    DEPS json mbedtls atlogger atcommons atchops atclient
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME atauth
    PACKAGE_DESCRIPTION "Atsign technology authentication library"
    PACKAGE_VERSION 0.0.1
    PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIR ${ATAUTH_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATAUTH_SOURCES}
    DEPS atlogger atcommons atchops atclient argparse
    EXTERNAL_DEPS mbedtls cjson
    INSTALL_TARGETS cjson mbedtls mbedx509 mbedcrypto everest p256m atclient atcommons atlogger atchops argparse
    BUILD_TESTS ${ATAUTH_BUILD_TESTS}
)

if(ATAUTH_BUILD_EXECUTABLES)
  add_compile_definitions(-DATAUTH_BUILD_EXECUTABLES=1)
  add_executable(atactivate ${CMAKE_CURRENT_LIST_DIR}/src/atactivate.c)
  target_link_libraries(
    atactivate
    PRIVATE cjson atlogger atcommons atchops atclient atauth
  )
  add_executable(at_auth_cli ${CMAKE_CURRENT_LIST_DIR}/src/auth_cli.c)
  target_link_libraries(
    at_auth_cli
    PRIVATE cjson atlogger atcommons atchops atclient atauth
  )
endif()

if(ATAUTH_BUILD_TESTS)
  enable_testing()
endif()
