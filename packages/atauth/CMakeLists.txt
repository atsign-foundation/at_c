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
  ${CMAKE_CURRENT_LIST_DIR}/src/atauth_build_atkeys_file_path.c
  ${CMAKE_CURRENT_LIST_DIR}/src/atauth_fetch_home_dir.c
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

if(NOT ESP_PLATFORM)
  include(GNUInstallDirs)

  # Determine if atchops is being built as a subproject using add_subdirectory()
  if(NOT DEFINED ATAUTH_AS_SUBPROJECT)
    set(ATAUTH_AS_SUBPROJECT ON)

    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
      set(ATAUTH_AS_SUBPROJECT OFF)
    endif()
  endif()

  message(STATUS "[ATAUTH] ATAUTH_AS_SUBPROJECT: ${ATAUTH_AS_SUBPROJECT}")

  # Import cjson
  if(NOT TARGET cjson)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_cjson.cmake)
  endif()

  # Import mbedtls
  if(NOT TARGET mbedcrypto OR NOT TARGET everest OR NOT TARGET p256m)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_mbedtls.cmake)
  endif()

  # Import atlogger
  if(NOT TARGET atlogger)
    set(atlogger_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atlogger)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atlogger.cmake)
  endif()

  # Import atcommons
  if(NOT TARGET atcommons)
    set(atcommons_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atcommons)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atcommons.cmake)
  endif()

  # Import atclient
  if(NOT TARGET atclient)
    set(atclient_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atclient)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atclient.cmake)
  endif()

  # Create library targets
  add_library(${PROJECT_NAME} STATIC ${ATAUTH_SOURCES})
  add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

  # LINK
  # Link include headers to library targets
  target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
      $<BUILD_INTERFACE:${ATAUTH_INCLUDE_DIR}>
      $<BUILD_INTERFACE:${cjson_SOURCE_DIR}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  set(
    ATAUTH_INSTALL_TARGETS
    cjson
    mbedtls
    mbedx509
    mbedcrypto
    everest
    p256m
    atclient
    atcommons
    atlogger
    atchops
  )
  target_link_libraries(${PROJECT_NAME} PUBLIC ${ATAUTH_INSTALL_TARGETS})

  # INSTALL
  # Install the include headers
  install(
    DIRECTORY ${ATAUTH_INCLUDE_DIR}/${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  install(
    FILES ${cJSON_SOURCE_DIR}/cJSON.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Install libraries to config target
  install(
    TARGETS ${PROJECT_NAME} ${ATAUTH_INSTALL_TARGETS}
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  # Build atactivate executable
  if(ATAUTH_BUILD_EXECUTABLES)
    add_executable(atactivate ${CMAKE_CURRENT_LIST_DIR}/src/atactivate.c)
    target_link_libraries(
      atactivate
      PRIVATE cjson atlogger atcommons atchops atclient atauth
    )
  endif()

  # EXPORT
  if(NOT ATAUTH_AS_SUBPROJECT)
    # install as a config.make
    install(
      EXPORT ${PROJECT_NAME}-config
      NAMESPACE ${PROJECT_NAME}::
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
      FILE ${PROJECT_NAME}-config.cmake
    )

    #export the config.cmake
    export(
      EXPORT ${PROJECT_NAME}-config
      NAMESPACE ${PROJECT_NAME}::
      FILE ${PROJECT_NAME}-config.cmake
    )
  endif()

  # Build the tests - No tests for ATAUTH yet
  # if(ATAUTH_BUILD_TESTS)
  #   enable_testing()
  #   add_subdirectory(tests)
  # endif()
endif()

