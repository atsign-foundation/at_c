# Set include directory and file sources
set(ATLOGGER_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(ATLOGGER_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/atlogger.c)

# Project setup
cmake_minimum_required(VERSION 3.19)

cmake_policy(SET CMP0135 NEW)

# register as an espidf component
if(ESP_PLATFORM)
  idf_component_register(
        SRCS ${ATLOGGER_SOURCES}
        INCLUDE_DIRS ${ATLOGGER_INCLUDE_DIR}
  )
  add_custom_command(
    TARGET ${COMPONENT_LIB}
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${ATLOGGER_INCLUDE_DIR}
      ${CMAKE_SOURCE_DIR}/include
    COMMAND
      ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}>
      ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
    COMMENT "Copying built archive file and header to lib directory..."
  )
endif()

project(
  atlogger
  VERSION 0.0.1
  DESCRIPTION "atlogger - tiny logging library"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

if(NOT ESP_PLATFORM)
  include(GNUInstallDirs)

  # Determine if atchops is being built as a subproject using add_subdirectory()
  if(NOT DEFINED ATLOGGER_AS_SUBPROJECT)
    set(ATLOGGER_AS_SUBPROJECT ON)
    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
      set(ATLOGGER_AS_SUBPROJECT OFF)
    endif()
  endif()
  message(STATUS "[ATLOGGER] ATLOGGER_AS_SUBPROJECT: ${ATLOGGER_AS_SUBPROJECT}")

  # Create library targets
  add_library(${PROJECT_NAME} STATIC ${ATLOGGER_SOURCES})

  # LINK
  # Link include headers to library targets
  target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
      $<BUILD_INTERFACE:${ATLOGGER_INCLUDE_DIR}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  # INSTALL
  # Install the include headers
  install(
    DIRECTORY ${ATLOGGER_INCLUDE_DIR}/${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Install libraries to config target
  install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  # EXPORT
  if(NOT ATLOGGER_AS_SUBPROJECT)
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

  # Build the tests - No tests for ATLOGGER yet
  # if(ATLOGGER_BUILD_TESTS)
  #   enable_testing()
  #   add_subdirectory(tests)
  # endif()
endif()
