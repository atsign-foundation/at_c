# targets
# -------
# argparse::argparse-static
# argparse::argparse-shared

# Set include directory and file sources
set(ARGPARSE_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(ARGPARSE_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/argparse.c)

# Project setup
cmake_minimum_required(VERSION 3.19)

cmake_policy(SET CMP0135 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME argparse
    PACKAGE_DESCRIPTION "argparse"
    PACKAGE_VERSION 0.0.1
    INCLUDE_DIR ${ARGPARSE_INCLUDE_DIR}
    PACKAGE_SOURCES ${ARGPARSE_SOURCES}
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME argparse
    PACKAGE_DESCRIPTION "argparse"
    PACKAGE_VERSION 0.0.1
    PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIR ${ARGPARSE_INCLUDE_DIR}
    PACKAGE_SOURCES ${ARGPARSE_SOURCES}
    DEPS ""
    EXTERNAL_DEPS ""
    INSTALL_TARGETS ""
    BUILD_TESTS OFF
)
