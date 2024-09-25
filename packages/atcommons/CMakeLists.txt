# Configurable options
option(ATCOMMONS_BUILD_TESTS "Build tests for atauth" OFF)

# Set include directory and file sources
set(ATCOMMONS_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
        ATCOMMONS_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/verb_builders/enroll_command_builder.c
        ${CMAKE_CURRENT_LIST_DIR}/src/enroll/enroll_operation.c
        ${CMAKE_CURRENT_LIST_DIR}/src/enroll/enroll_status.c
        ${CMAKE_CURRENT_LIST_DIR}/src/enroll/enroll_namespace_struct.c
        ${CMAKE_CURRENT_LIST_DIR}/src/enroll/enroll_params.c
        ${CMAKE_CURRENT_LIST_DIR}/src/test.c
        src/verb_builders/cram_command_builder.c
        include/atcommons/cram_command_builder.h)

# Project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

## not adding the esp target yet

project(
        atcommons
        VERSION 0.0.1
        DESCRIPTION "atcommons - common at_platform utilities and implementations"
        HOMEPAGE_URL https://atsign.com
        LANGUAGES C
)

if (NOT ESP_PLATFORM)
    include(GNUInstallDirs)

    # Determine if atchops is being built as a subproject using add_subdirectory()
    if (NOT DEFINED ATCOMMONS_AS_SUBPROJECT)
        set(ATCOMMONS_AS_SUBPROJECT ON)

        if (CMAKE_CURRENT_SOURCES_DIR STREQUAL CMAKE_SOURCE_DIR)
            set(ATCOMMONS_AS_SUBPROJECT OFF)
        endif ()
    endif ()

    message(STATUS "[ATCOMMONS] ATCOMMONS_AS_SUBPROJECT: ${ATCOMMONS_AS_SUBPROJECT}")

    # Import cjson
    if (NOT TARGET cjson)
        include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/find_cjson.cmake)
    endif ()

    # Import atlogger
    if (NOT TARGET atlogger)
        set(atlogger_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../atlogger)
        include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/atlogger.cmake)
    endif ()

    # Create library targets
    add_library(${PROJECT_NAME} STATIC ${ATCOMMONS_SOURCES})
    add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

    # LINK
    # Link include headers to library targets
    target_include_directories(
            ${PROJECT_NAME}
            PUBLIC
            $<BUILD_INTERFACE:${ATCOMMONS_INCLUDE_DIR}>
            $<BUILD_INTERFACE:${cjson_SOURCE_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    set(
            ATCOMMONS_INSTALL_TARGETS
            atlogger
            cjson)

    install(
            DIRECTORY ${ATCOMMONS_INCLUDE_DIR}/${PROJECT_NAME}
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    install(
            FILES ${cjson_SOURCE_DIR}/cJSON.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # Install libraries to config target
    install(
            TARGETS ${PROJECT_NAME}
            EXPORT ${PROJECT_NAME}-config
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

    # EXPORT
    if (NOT ATCOMMONS_AS_SUBPROJECT)
        message("[ATCOMMONS] NOT as SUBPROJECT")
        # Export the library
        export(PACKAGE ${PROJECT_NAME})

        # Install as a config.make
        install(
                EXPORT ${PROJECT_NAME}-config
                NAMESPACE ${PROJECT_NAME}-config.cmake
                DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
                FILE ${PROJECT_NAME}-config.cmake
        )

        #export the config.cmake
        export(
                EXPORT ${PROJECT_NAME}-config
                NAMESPACE ${PROJECT_NAME}::
                FILE "cmake/${PROJECT_NAME}-config.cmake"
        )
    endif ()

    # Build the tests - No tests for ATCOMMONS yet
    # if(ATCOMMONS_BUILD_TESTS)
    #   enable_testing()
    #   add_subdirectory(tests)
    # endif()
endif ()