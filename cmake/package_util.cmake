set(ATSDK_CMAKE_DIR ${CMAKE_CURRENT_LIST_DIR})
if(ATSDK_USE_SHARED_LIBS)
  # predetermine include dirs for shared libs if we will be linking to them
  find_path(mbedtls_INCLUDE_DIR NAMES mbedtls/x509.h REQUIRED)
  # find_path(p256m_INCLUDE_DIR NAMES mbedtls/x509.h)
  # find_path(everest_INCLUDE_DIR NAMES everest/everest.h REQUIRED)
  find_path(cjson_INCLUDE_DIR NAMES cjson/cJSON.h REQUIRED)
endif()

set(mbedtls_LIB_NAMES libmbedtls.so libmbedcrypto.so libmbedx509.so)
set(cjson_LIB_NAMES libcjson.so)

# build a package using cmake
function(build_atsdk_package)
  set(
    oneValueArgs
    PACKAGE_NAME
    PACKAGE_DESCRIPTION
    PACKAGE_VERSION
    PACKAGE_DIR
    INCLUDE_DIR
    BUILD_TESTS
  )
  set(multiValueArgs PACKAGE_SOURCES DEPS EXTERNAL_DEPS INSTALL_TARGETS)
  set(options)
  cmake_parse_arguments(
    PARSE_ARGV
    0
    arg
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
  )

  # make sure this is always unset at the start of the function
  unset(cJSON_SOURCE_DIR)

  project(
    ${arg_PACKAGE_NAME}
    VERSION ${arg_PACKAGE_VERSION}
    DESCRIPTION ${arg_PACKAGE_DESCRIPTION}
    HOMEPAGE_URL https://github.com/atsign-foundation/at_c
    LANGUAGES C
  )

  if(NOT ESP_PLATFORM)
    include(GNUInstallDirs)

    # Determine if project is being built as a subproject using add_subdirectory()
    if(arg_PACKAGE_DIR STREQUAL CMAKE_SOURCE_DIR)
      set(PACKAGE_AS_SUBPROJECT OFF)
    else()
      set(PACKAGE_AS_SUBPROJECT ON)
    endif()

    message(
      STATUS
      "[${arg_PACKAGE_NAME}] PACKAGE_AS_SUBPROJECT: ${PACKAGE_AS_SUBPROJECT}"
    )

    foreach(package ${arg_DEPS})
      set(${package}_DIR ${ATSDK_CMAKE_DIR}/../packages/${package})
      include(${ATSDK_CMAKE_DIR}/${package}.cmake)
    endforeach()

    # Create library targets
    add_library(${PROJECT_NAME} STATIC ${arg_PACKAGE_SOURCES})

    if(ATSDK_USE_SHARED_LIBS)
      foreach(package ${arg_EXTERNAL_DEPS})
        target_include_directories(${PROJECT_NAME} PUBLIC ${${package}_INCLUDE_DIR})
        foreach(lib ${${package}_LIB_NAMES})
          find_library(${lib}_lib_path NAMES ${lib} PATHS /usr/lib /usr/lib64 /usr/local/lib NO_CACHE REQUIRED NO_DEFAULT_PATH NO_PACKAGE_ROOT_PATH NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH NO_CMAKE_INSTALL_PREFIX)
          message(STATUS ${lib} -> ${${lib}_lib_path})
          target_link_libraries(${PROJECT_NAME} PRIVATE ${${lib}_lib_path})
        endforeach()
      endforeach()
    else()
      foreach(package ${arg_EXTERNAL_DEPS})
        include(${ATSDK_CMAKE_DIR}/find_${package}.cmake)
      endforeach()
    endif()


    # LINK
    # Link include headers to library targets
    target_include_directories(
      ${PROJECT_NAME}
      PUBLIC
        $<BUILD_INTERFACE:${arg_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${cJSON_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      message(STATUS "LINKING PRIVATE HEADERS FOR DEBUG MODE")
      target_include_directories(
        ${PROJECT_NAME}
        PUBLIC $<BUILD_INTERFACE:${arg_PACKAGE_DIR}/src>
      )
    endif()

    # Link dependencies to library targets
    if(ATSDK_USE_SHARED_LIBS)
      target_link_libraries(${PROJECT_NAME} PUBLIC ${arg_DEPS})
    else()
      target_link_libraries(${PROJECT_NAME} PUBLIC ${arg_INSTALL_TARGETS})
    endif()

    # INSTALL
    # Install the include headers
    install(
      DIRECTORY ${arg_INCLUDE_DIR}/${PROJECT_NAME}
      DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # Install libraries to config target
    if(ATSDK_USE_SHARED_LIBS)
      install(
        TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-config
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      )
    else()
      install(
        TARGETS ${PROJECT_NAME} ${arg_INSTALL_TARGETS}
        EXPORT ${PROJECT_NAME}-config
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      )
    endif()

    # EXPORT
    if(NOT PACKAGE_AS_SUBPROJECT)
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
    if(arg_BUILD_TESTS)
      add_subdirectory(${arg_PACKAGE_DIR}/tests)
    endif()
  endif()
endfunction()

# add an espidf component to the build
function(add_atsdk_espidf_component)
  set(oneValueArgs PACKAGE_NAME PACKAGE_DESCRIPTION PACKAGE_VERSION)
  set(multiValueArgs INCLUDE_DIR SOURCES DEPS)
  set(options "")
  cmake_parse_arguments(
    PARSE_ARGV
    0
    arg
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
  )

  idf_component_register(
        SRCS ${arg_SOURCES}
        INCLUDE_DIRS ${arg_INCLUDE_DIR}
        REQUIRES ${arg_DEPS}
  )

  add_custom_command(
    TARGET ${COMPONENT_LIB}
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${arg_INCLUDE_DIR}
      ${CMAKE_SOURCE_DIR}/include
    COMMAND
      ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}>
      ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
    COMMENT "Copying built archive file and header to lib directory..."
  )

  project(
    ${arg_PACKAGE_NAME}
    VERSION ${arg_VERSION}
    DESCRIPTION ${arg_DESCRIPTION}
    HOMEPAGE_URL https://github.com/atsign-foundation/at_c
    LANGUAGES C
  )
endfunction()
