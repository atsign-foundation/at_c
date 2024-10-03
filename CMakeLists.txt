# Configurable options
set(TARGET_ESPIDF FALSE CACHE BOOL "Build for the espidf platform")
option(ATSDK_BUILD_TESTS "Build tests for atsdk" OFF)

# Basic project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)
include(GNUInstallDirs)

project(
  atsdk
  VERSION 0.0.1
  DESCRIPTION "Atsign's atSDK library"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

# Determine if atchops is being built as a subproject using add_subdirectory()
if(NOT DEFINED ATSDK_AS_SUBPROJECT)
  set(ATSDK_AS_SUBPROJECT ON)
  if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(ATSDK_AS_SUBPROJECT OFF)
  endif()
endif()
message(STATUS "[ATSDK] ATSDK_AS_SUBPROJECT: ${ATSDK_AS_SUBPROJECT}")

# install each package
message(STATUS "Building atlogger")
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/packages/atlogger)

message(STATUS "Building atchops")
set(ATCHOPS_BUILD_TESTS ${ATSDK_BUILD_TESTS})
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/packages/atchops)

message(STATUS "Building atclient")
set(ATCLIENT_BUILD_TESTS ${ATSDK_BUILD_TESTS})
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/packages/atclient)

message(STATUS "Building atcommons")
set(ATCOMMONS_BUILD_TESTS ${ATSDK_BUILD_TESTS})
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/packages/atcommons)

message(STATUS "Building atauth")
set(ATAUTH_BUILD_TESTS ${ATSDK_BUILD_TESTS})
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/packages/atauth)

if(NOT ESP_PLATFORM)
  # install dependencies
  set(
    ATSDK_TARGETS
    mbedtls
    mbedx509
    mbedcrypto
    everest
    p256m
    uuid4-static
    atchops
    cjson
    atlogger
    atclient
          atcommons
  )

  install(
    TARGETS ${ATSDK_TARGETS}
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  # export dependencies
  if(NOT ATSDK_AS_SUBPROJECT)
    export(PACKAGE ${PROJECT_NAME})

    # install as a config.cmake
    install(
      EXPORT ${PROJECT_NAME}-config
      NAMESPACE ${PROJECT_NAME}::
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
      FILE ${PROJECT_NAME}-config.cmake
    )

    # export the config.cmake
    export(
      EXPORT ${PROJECT_NAME}-config
      NAMESPACE ${PROJECT_NAME}::
      FILE "cmake/${PROJECT_NAME}-config.cmake"
    )
  endif()
endif()
