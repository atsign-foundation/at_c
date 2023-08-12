cmake_minimum_required(VERSION 3.19)

project(
    atchops
    VERSION 1.0.0
    DESCRIPTION "The at_client implemented in C"
    HOMEPAGE_URL https://atsign.com
    LANGUAGES C
)

# #########################################################
# 0. Variables - you are free to edit anything in this step
# #########################################################

# add source files manually here, globs are apparently bad practice
set(atchops_srcs
    ${CMAKE_CURRENT_LIST_DIR}/src/aes_ctr.c
    ${CMAKE_CURRENT_LIST_DIR}/src/base64.c
    ${CMAKE_CURRENT_LIST_DIR}/src/byteutil.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rsa.c
    ${CMAKE_CURRENT_LIST_DIR}/src/sha.c
)

set(atchops_include_dir
    ${CMAKE_CURRENT_LIST_DIR}/include # not `include/atchops` because we want clients to include it like #include "atchops/atchops.h"
)

option(ATCHOPS_BUILD_TESTS "Build tests" OFF)

# #########################################################
# 1. Include CMake modules
# #########################################################

# ${CMAKE_INSTALL_*} variables are defined in GNUInstallDirs and changes according to OS. E.g. on Linux & MacOS, ${CMAKE_INSTALL_LIBDIR} is /usr/local/lib, but on Windows it may be C:\Program Files\atchops\lib
include(GNUInstallDirs)

# #########################################################
# 2. find_package MbedTLS
# #########################################################ß

# You can install MbedTLS with `cmake -S . -B build && sudo cmake --build build --target install` on the root of MbedTLS's repo or source code release
find_package(MbedTLS REQUIRED)

# MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx509 are now available
message(STATUS "Successfully fetched MbedTLS")

# #########################################################
# 3. Create atchops target
# #########################################################

add_library(atchops STATIC ${atchops_srcs})

# add include/atchops/*.h to `atchops`
# we put *.h inside of nested atchops/ directory so that it will be included like #include "atchops/atchops.h"
target_include_directories(atchops PUBLIC
    $<BUILD_INTERFACE:${atchops_include_dir}> # when `cmake ..` look for headers when building in ./packages/atchops/include/atchops/*.h
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}> # when `make install` look inside of something like /usr/local/include/**
)

# add MbedTLS dependencies to `atchops`
target_link_libraries(atchops PRIVATE MbedTLS::mbedcrypto)

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
install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # install goes to: /usr/local/lib/atchops/libatchops.a
)

# Export atchops-config.cmake to /usr/local/lib/cmake/atchops/atchops-config.cmake
install(
	EXPORT ${PROJECT_NAME}-config
	NAMESPACE ${PROJECT_NAME}::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
	FILE ${PROJECT_NAME}-config.cmake
)

# #########################################################
# Generate tests
# #########################################################

if(ATCHOPS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
