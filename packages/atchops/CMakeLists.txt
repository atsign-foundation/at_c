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

# #########################################################
# 1. Include CMake modules
# #########################################################

# FetchContent is a CMake v3.11+ module that downloads content at configure time
include(FetchContent)

# ${CMAKE_INSTALL_*} variables are defined in GNUInstallDirs and changes according to OS. E.g. on Linux & MacOS, ${CMAKE_INSTALL_LIBDIR} is /usr/local/lib, but on Windows it may be C:\Program Files\atchops\lib
include(GNUInstallDirs)

# #########################################################
# 2. Use FetchContent to get MbedTLS namespace
# #########################################################

# v3.4.1 Release
FetchContent_Declare(
    MbedTLS
    URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
    URL_HASH SHA256=a420fcf7103e54e775c383e3751729b8fb2dcd087f6165befd13f28315f754f5 # hash for v3.4.1 .tar.gz release source code
    OVERRIDE_FIND_PACKAGE
)

# From `development` branch
# FetchContent_Declare(
#     MbedTLS
#     GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
#     GIT_TAG 2588f8d36d8f519c6e37b8a8f8977ba2aa9c72a4
#     # OVERRIDE_FIND_PACKAGE
# )

# FetchContent_MakeAvailable(MbedTLS) # ensures named dependencies have been populated
find_package(MbedTLS REQUIRED)

# MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx50 are now available
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

# Installs atchops and mbedcrypto and tells `atchops-config.cmake` where to find mbedtls stuff
install(
    TARGETS ${PROJECT_NAME} mbedcrypto
    EXPORT ${PROJECT_NAME}-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # install goes to: /usr/local/lib/atchops/libatchops.a
)

install(
	EXPORT ${PROJECT_NAME}-config
	NAMESPACE ${PROJECT_NAME}::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
	FILE ${PROJECT_NAME}-config.cmake
)
