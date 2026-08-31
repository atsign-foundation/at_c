# Configurable options
option(ATCLIENT_BUILD_TESTS "Build tests for atclient" OFF)

# Set include directory and file sources
set(ATCLIENT_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(ATCLIENT_PROTECTED_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(
  ATCLIENT_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_delete.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_atkeys.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_public_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_self_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_shared_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_put_public_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_put_self_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_put_shared_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_utils.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atkey.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atkeys.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atkeys_file.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atnotification.c
  ${CMAKE_CURRENT_LIST_DIR}/src/connection_hooks.c
  ${CMAKE_CURRENT_LIST_DIR}/src/connection.c
  ${CMAKE_CURRENT_LIST_DIR}/src/socket.c
  ${CMAKE_CURRENT_LIST_DIR}/src/socket_mbedtls.c
  ${CMAKE_CURRENT_LIST_DIR}/src/encryption_key_helpers.c
  ${CMAKE_CURRENT_LIST_DIR}/src/metadata.c
  ${CMAKE_CURRENT_LIST_DIR}/src/monitor.c
  ${CMAKE_CURRENT_LIST_DIR}/src/notify.c
  ${CMAKE_CURRENT_LIST_DIR}/src/notify_params.c
  ${CMAKE_CURRENT_LIST_DIR}/src/request_options.c
  ${CMAKE_CURRENT_LIST_DIR}/src/string_utils.c
  # protected files
  ${CMAKE_CURRENT_LIST_DIR}/src/atserver_message.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atdirectory.c
)

# Project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME atclient
    PACKAGE_DESCRIPTION "Atsign technology client library"
    PACKAGE_VERSION 0.4.0
    INCLUDE_DIR ${ATCLIENT_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATCLIENT_SOURCES}
    DEPS mbedtls atchops atlogger atcommons json
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME atclient
    PACKAGE_DESCRIPTION "Atsign technology client library"
    PACKAGE_VERSION 0.4.0
    PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIR ${ATCLIENT_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATCLIENT_SOURCES}
    DEPS atlogger atchops atcommons
    EXTERNAL_DEPS mbedtls cjson
    INSTALL_TARGETS atlogger atcommons atchops mbedtls mbedx509 mbedcrypto everest p256m cjson
    BUILD_TESTS ${ATCLIENT_BUILD_TESTS}
)

if(ATCLIENT_BUILD_TESTS)
  enable_testing()
endif()
