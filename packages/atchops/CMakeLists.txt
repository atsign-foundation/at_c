# Configurable options
option(ATCHOPS_BUILD_TESTS "Build tests for atchops" OFF)

# Set include directory and file sources
set(ATCHOPS_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
  ATCHOPS_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/aes.c
  ${CMAKE_CURRENT_LIST_DIR}/src/aesctr.c
  ${CMAKE_CURRENT_LIST_DIR}/src/base64.c
  ${CMAKE_CURRENT_LIST_DIR}/src/constants.c
  ${CMAKE_CURRENT_LIST_DIR}/src/iv.c
  ${CMAKE_CURRENT_LIST_DIR}/src/rsa.c
  ${CMAKE_CURRENT_LIST_DIR}/src/rsakey.c
  ${CMAKE_CURRENT_LIST_DIR}/src/sha.c
  ${CMAKE_CURRENT_LIST_DIR}/src/uuid.c
)

# Project setup
cmake_minimum_required(VERSION 3.19)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

# register as an espidf component
if(ESP_PLATFORM)
  idf_component_register(
        SRCS ${ATCHOPS_SOURCES}
        INCLUDE_DIRS ${ATCHOPS_INCLUDE_DIR}
        REQUIRES mbedtls
  )
  add_custom_command(
    TARGET ${COMPONENT_LIB}
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${ATCHOPS_INCLUDE_DIR}
      ${CMAKE_SOURCE_DIR}/include
    COMMAND
      ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}>
      ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
    COMMENT "Copying built archive file and header to lib directory..."
  )
endif()

project(
  atchops
  VERSION 0.0.1
  DESCRIPTION "atchops - cryptographic hash operations"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

if(NOT ESP_PLATFORM)
  include(GNUInstallDirs)

  # Determine if atchops is being built as a subproject
  if(NOT DEFINED ATCHOPS_AS_SUBPROJECT)
    set(ATCHOPS_AS_SUBPROJECT ON)
    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
      set(ATCHOPS_AS_SUBPROJECT OFF)
    endif()
  endif()
  message(STATUS "[ATCHOPS] ATCHOPS_AS_SUBPROJECT: ${ATCHOPS_AS_SUBPROJECT}")

  # Import mbedtls
  if(NOT TARGET mbedcrypto OR NOT TARGET everest OR NOT TARGET p256m)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_mbedtls.cmake)
  endif()

  # Import uuid4
  if(NOT TARGET uuid4-static)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_uuid4.cmake)
  endif()

  # Import atlogger
  if(NOT TARGET atlogger)
    set(atlogger_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atlogger)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atlogger.cmake)
  endif()

  # Create library targets
  add_library(${PROJECT_NAME} STATIC ${ATCHOPS_SOURCES})
  add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

  # LINK
  # Link include headers to library targets
  target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
      $<BUILD_INTERFACE:${ATCHOPS_INCLUDE_DIR}> # when `cmake ..` look for headers when building in ./packages/atchops/include/atchops/*.h
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}> # when `make install` look inside of something like /usr/local/include/**
  )

  # Link dependencies to library targets
  set(
    ATCHOPS_INSTALL_TARGETS
    atlogger
    mbedcrypto
    everest
    p256m
    uuid4-static
  )

  target_link_libraries(${PROJECT_NAME} PUBLIC ${ATCHOPS_INSTALL_TARGETS})
  # INSTALL
  # Install the include headers
  install(
    DIRECTORY ${ATCHOPS_INCLUDE_DIR}/${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Install libraries to config target
  install(
    TARGETS ${PROJECT_NAME} ${ATCHOPS_INSTALL_TARGETS}
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  # EXPORT
  if(NOT ATCHOPS_AS_SUBPROJECT)
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
      FILE "cmake/${PROJECT_NAME}-config.cmake"
    )
  endif()

  # Build the tests
  if(ATCHOPS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
  endif()
endif()
