# Configurable options
option(ATAUTH_BUILD_TESTS "Build tests for atauth" OFF)
option(ATAUTH_BUILD_EXECUTABLES "Build executables in atauth" ON)

# Set include directory and file sources
set(ATAUTH_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
  ATAUTH_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/apkam_keys.c
  ${CMAKE_CURRENT_LIST_DIR}/src/at_activate.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_namespace.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_operation.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_params.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_request.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_response.c
  ${CMAKE_CURRENT_LIST_DIR}/src/params.c
  ${CMAKE_CURRENT_LIST_DIR}/src/run_onboard_command.c
  ${CMAKE_CURRENT_LIST_DIR}/src/run_enroll_command.c
  ${CMAKE_CURRENT_LIST_DIR}/src/wait_for_enrollment.c
)

# Project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

## not adding the esp target yet

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME atauth
    PACKAGE_DESCRIPTION "Atsign technology authentication library"
    PACKAGE_VERSION 0.4.0
    INCLUDE_DIR ${ATAUTH_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATAUTH_SOURCES}
    DEPS json mbedtls atlogger atcommons atchops atclient
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME atauth
    PACKAGE_DESCRIPTION "Atsign technology authentication library"
    PACKAGE_VERSION 0.4.0
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
  add_executable(at_activate ${CMAKE_CURRENT_LIST_DIR}/src/at_activate.c)
  target_link_libraries(
    at_activate
    PRIVATE cjson atlogger atcommons atchops atclient atauth argparse
  )
endif()

if(ATAUTH_BUILD_TESTS)
  enable_testing()
endif()
