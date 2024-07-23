# Configurable options
option(ATCLIENT_BUILD_TESTS "Build tests for atclient" OFF)

# Set include directory and file sources
set(ATCLIENT_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
  ATCLIENT_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_delete.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_atkeys.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_publickey.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_selfkey.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_get_sharedkey.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_put.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient_utils.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atclient.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atkey.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atkeys.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atkeysfile.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atnotification.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atsign.c
  ${CMAKE_CURRENT_LIST_DIR}/src/connection.c
  ${CMAKE_CURRENT_LIST_DIR}/src/encryption_key_helpers.c
  ${CMAKE_CURRENT_LIST_DIR}/src/metadata.c
  ${CMAKE_CURRENT_LIST_DIR}/src/monitor.c
  ${CMAKE_CURRENT_LIST_DIR}/src/notify.c
  ${CMAKE_CURRENT_LIST_DIR}/src/stringutils.c
)

# Project setup
cmake_minimum_required(VERSION 3.19)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

# register as an espidf component
if(ESP_PLATFORM)
  # Run special CMake commands for ESP32
  idf_component_register(
  SRCS ${ATCLIENT_SOURCES}
  INCLUDE_DIRS ${ATCLIENT_INCLUDE_DIR}
  REQUIRES mbedtls atchops
  )

  # Copy header files to include directory and libraries to lib directory
  add_custom_command(
    TARGET ${COMPONENT_LIB}
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${ATCLIENT_INCLUDE_DIR}
      ${CMAKE_SOURCE_DIR}/include
    COMMAND
      ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}>
      ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
    COMMENT "Copying built archive file and header to lib directory..."
  )
endif()

project(
  atclient
  VERSION 0.0.1
  DESCRIPTION "Atsign technology client library"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

if(NOT ESP_PLATFORM)
  include(GNUInstallDirs)

  # Determine if atclient is being built as a subproject
  if(NOT DEFINED ATCLIENT_AS_SUBPROJECT)
    set(ATCLIENT_AS_SUBPROJECT ON)

    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
      set(ATCLIENT_AS_SUBPROJECT OFF)
    endif()
  endif()
  message(STATUS "[ATCLIENT] ATCLIENT_AS_SUBPROJECT: ${ATCLIENT_AS_SUBPROJECT}")

  # Import mbedtls
  if(NOT TARGET mbedcrypto OR NOT TARGET everest OR NOT TARGET p256m)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_mbedtls.cmake)
  endif()

  # Import cjson
  if(NOT TARGET cjson)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_cjson.cmake)
  endif()

  # Import atlogger
  if(NOT TARGET atlogger)
    set(atlogger_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atlogger)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atlogger.cmake)
  endif()

  # Import atchops
  if(NOT TARGET atchops)
    set(atchops_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atchops)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atchops.cmake)
  endif()

  # Create library targets
  add_library(${PROJECT_NAME} STATIC ${ATCLIENT_SOURCES})
  add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

  # LINK
  # Link include headers to library targets
  target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
      $<BUILD_INTERFACE:${ATCLIENT_INCLUDE_DIR}>
      $<BUILD_INTERFACE:${cjson_SOURCE_DIR}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  # Link dependencies to library targets 
  set(
    ATCLIENT_INSTALL_TARGETS
    atlogger
    atchops
    mbedtls
    mbedx509
    mbedcrypto
    everest
    p256m
    uuid4-static
    cjson
  )
  target_link_libraries(${PROJECT_NAME} PUBLIC ${ATCLIENT_INSTALL_TARGETS})

  # INSTALL
  # Install the include headers
  install(
    DIRECTORY ${ATCLIENT_INCLUDE_DIR}/${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )
  install(
    FILES ${cjson_SOURCE_DIR}/cJSON.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Install libraries to config target
  install(
    TARGETS ${ATCLIENT_INSTALL_TARGETS}
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  # EXPORT
  if(NOT ATCLIENT_AS_SUBPROJECT)
    # Export the library
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
      FILE ${PROJECT_NAME}-config.cmake
    )
  endif()

  # Build the tests
  if(ATCLIENT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests)
  endif()
endif()
