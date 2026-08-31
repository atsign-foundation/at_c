# Set include directory and file sources
set(ATLOGGER_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(ATLOGGER_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/atlogger.c)

# Project setup
cmake_minimum_required(VERSION 3.19)

cmake_policy(SET CMP0135 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME atlogger
    PACKAGE_DESCRIPTION "atlogger - tiny logging library"
    PACKAGE_VERSION 0.4.0
    INCLUDE_DIR ${ATLOGGER_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATLOGGER_SOURCES}
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME atlogger
    PACKAGE_DESCRIPTION "atlogger - tiny logging library"
    PACKAGE_VERSION 0.4.0
    PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIR ${ATLOGGER_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATLOGGER_SOURCES}
    DEPS ""
    EXTERNAL_DEPS ""
    INSTALL_TARGETS ""
    BUILD_TESTS OFF
)
