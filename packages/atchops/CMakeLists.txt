# Configurable options
option(ATCHOPS_BUILD_TESTS "Build tests for atchops" OFF)

# Set include directory and file sources
set(ATCHOPS_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
  ATCHOPS_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/aes_ctr.c
  ${CMAKE_CURRENT_LIST_DIR}/src/aes.c
  ${CMAKE_CURRENT_LIST_DIR}/src/base64.c
  ${CMAKE_CURRENT_LIST_DIR}/src/mbedtls.c
  ${CMAKE_CURRENT_LIST_DIR}/src/iv.c
  ${CMAKE_CURRENT_LIST_DIR}/src/rsa_key.c
  ${CMAKE_CURRENT_LIST_DIR}/src/rsa.c
  ${CMAKE_CURRENT_LIST_DIR}/src/sha.c
  ${CMAKE_CURRENT_LIST_DIR}/src/uuid.c
  ${CMAKE_CURRENT_LIST_DIR}/src/hex.c
  ${CMAKE_CURRENT_LIST_DIR}/src/utf8.c
)

# Project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME atchops
    PACKAGE_DESCRIPTION "atchops - cryptographic hash operations"
    PACKAGE_VERSION 0.4.0
    INCLUDE_DIR ${ATCHOPS_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATCHOPS_SOURCES}
    DEPS mbedtls atlogger
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME atchops
    PACKAGE_DESCRIPTION "atchops - cryptographic hash operations"
    PACKAGE_VERSION 0.4.0
    PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIR ${ATCHOPS_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATCHOPS_SOURCES}
    DEPS atlogger
    EXTERNAL_DEPS mbedtls
    INSTALL_TARGETS atlogger mbedcrypto everest p256m
    BUILD_TESTS ${ATCHOPS_BUILD_TESTS}
)

if(ATCHOPS_BUILD_TESTS)
  enable_testing()
endif()
