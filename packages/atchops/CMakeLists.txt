cmake_minimum_required(VERSION 3.19)

# #########################################################
# 0. Variables - you are free to edit anything in this step
# #########################################################

# add source files manually here, globs are apparently bad practice
set(atchops_srcs
    ${CMAKE_CURRENT_LIST_DIR}/src/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/src/aesctr.c
    ${CMAKE_CURRENT_LIST_DIR}/src/base64.c
    ${CMAKE_CURRENT_LIST_DIR}/src/iv.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rsakey.c
    ${CMAKE_CURRENT_LIST_DIR}/src/sha.c
    ${CMAKE_CURRENT_LIST_DIR}/src/uuid.c
)

set(atchops_include_dir
    ${CMAKE_CURRENT_LIST_DIR}/include # not `include/atchops` because we want clients to include it like #include "atchops/atchops.h"
)

cmake_policy(SET CMP0135 NEW)

option(ATCHOPS_BUILD_TESTS "Build tests" OFF)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${atchops_srcs}
        INCLUDE_DIRS ${atchops_include_dir}
        REQUIRES mbedtls
    )
    add_custom_command(
        TARGET ${COMPONENT_LIB}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${atchops_include_dir} ${CMAKE_SOURCE_DIR}/include
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}> ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
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
    # #########################################################
    # 1. Include CMake modules
    # #########################################################

    # FetchContent is a module that allows us to fetch dependencies from GitHub, URL, etc. and build them from source in configure step
    include(FetchContent)

    # ${CMAKE_INSTALL_*} variables are defined in GNUInstallDirs and changes according to OS. E.g. on Linux & MacOS, ${CMAKE_INSTALL_LIBDIR} is /usr/local/lib, but on Windows it may be C:\Program Files\atchops\lib
    include(GNUInstallDirs)

    # #########################################################
    # 2. Dependencies
    # #########################################################

    # #########################################################
	# 2A. MbedTLS
	# #########################################################
    find_package(MbedTLS QUIET)
    if(NOT MbedTLS_FOUND)
        message(STATUS "[ATCHOPS] MbedTLS not found, fetching from GitHub...")
        FetchContent_Declare(
            MbedTLS
            URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
            URL_HASH SHA256=a420fcf7103e54e775c383e3751729b8fb2dcd087f6165befd13f28315f754f5 # hash for v3.4.1 .tar.gz release source code
        )
        list(APPEND ATCHOPS_TARGETS_TO_INSTALL mbedcrypto) # since FetchContent imports the third-party library as if we wrote it ourselves, we also need to export it https://stackoverflow.com/questions/71541589/how-to-exporting-targets-fetched-with-fetchcontent
        list(APPEND ATCHOPS_MAKE_AVAILABLE MbedTLS) # make this available later on, when we make all modules available all at once
    endif()

    # #########################################################
	# 2B. uuid4
	# #########################################################
	find_package(uuid4 QUIET)
	if(NOT uuid4_FOUND)
		message(STATUS "[ATCHOPS] uuid4 not found, fetching from GitHub..")
		FetchContent_Declare(
			uuid4
			URL https://github.com/atsign-foundation/uuid4/releases/download/v1.0.1/uuid4-v1.0.1.zip
            URL_HASH SHA256=6782f4bf194e108c0c76aa6ecd117048f3751f11e405a93fcb307cdcb39b34e2
            # URL_HASH MD5=6dd2aae881ecd3f40e9c4f12f037142a
		)
		list(APPEND ATCHOPS_TARGETS_TO_INSTALL uuid4-static) # since we've fetched it, we have to install it
		list(APPEND ATCHOPS_MAKE_AVAILABLE uuid4) # we have to make it available later on with FetchContent_MakeAvailable
	else()
		message(STATUS "[ATCHOPS] uuid4 found package..")
	endif()
    
    # 2z. Fetch dependencies
    # MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx509 are now available
    if(ATCHOPS_MAKE_AVAILABLE)
        FetchContent_MakeAvailable(${ATCHOPS_MAKE_AVAILABLE}) # ensures named dependencies have been populated
    endif()

    # #########################################################
    # 3. Create atchops target
    # #########################################################
    add_library(${PROJECT_NAME} STATIC ${atchops_srcs})

    # add include/atchops/*.h to `atchops`
    # we put *.h inside of nested atchops/ directory so that it will be included like #include "atchops/atchops.h"
    target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${atchops_include_dir}> # when `cmake ..` look for headers when building in ./packages/atchops/include/atchops/*.h
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}> # when `make install` look inside of something like /usr/local/include/**
    )

    # add MbedTLS dependencies to `atchops`
    target_link_libraries(${PROJECT_NAME} PUBLIC 
        MbedTLS::mbedcrypto
        uuid4::uuid4-static
    )

    # #########################################################
    # 4. Install atchops
    # doing `make install` or `cmake --build build --target install` (<- recommended) will run all this stuff below
    # (this stuff is pretty much analogous to doing something like dart pub add)
    # #########################################################

    # Installs headers to /usr/local/include/atchops/*.h
    install(
        DIRECTORY ${atchops_include_dir}/${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # install goes to: /usr/local/include/atchops/*.h
    )

    # Installs atchops and mbedcrypto and tells `atchops-config.cmake` where to find stuff
    list(APPEND ATCHOPS_TARGETS_TO_INSTALL ${PROJECT_NAME}) # install atchops

    foreach(target ${ATCHOPS_TARGETS_TO_INSTALL})
        message(STATUS "[ATCHOPS] Installing ${target}...")
        install(
            TARGETS ${target}
            EXPORT ${PROJECT_NAME}-config
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # install goes to: /usr/local/lib/atchops/libatchops.a
        )
    endforeach()

    # Export atchops-config.cmake to /usr/local/lib/cmake/atchops/atchops-config.cmake
    install(
        EXPORT ${PROJECT_NAME}-config
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        FILE ${PROJECT_NAME}-config.cmake
    )

    # #########################################################
    # 5. Export in case people add us via add_subdirectory
    # #########################################################
    export(PACKAGE ${PROJECT_NAME})

    export(
        EXPORT ${PROJECT_NAME}-config
        NAMESPACE ${PROJECT_NAME}::
        FILE "cmake/${PROJECT_NAME}-config.cmake")

    add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

    # #########################################################
    # 6. Generate tests
    # #########################################################
    if(ATCHOPS_BUILD_TESTS)
        enable_testing()
        add_subdirectory(tests)
    endif()
endif()