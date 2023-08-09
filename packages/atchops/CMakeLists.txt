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

FetchContent_Declare(
    MbedTLS
    URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
    URL_HASH SHA256=a420fcf7103e54e775c383e3751729b8fb2dcd087f6165befd13f28315f754f5 # hash for v3.4.1 .tar.gz release source code
)

FetchContent_MakeAvailable(MbedTLS) # ensures named dependencies have been populated

# MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx50 are now available
message(STATUS "Successfully fetched MbedTLS v3.4.1")

# #########################################################
# 3. Create atchops target
# #########################################################

add_library(atchops STATIC ${atchops_srcs})

# add include/atchops/*.h to `atchops`
# we put *.h inside of nested atchops/ directory so that it will be included like #include "atchops/atchops.h"
target_include_directories(atchops PUBLIC
    $<BUILD_INTERFACE:${atchops_include_dir}> # when `cmake ..` look for headers when building in ./packages/atchops/include/atchops/*.h
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}> # when `make install` look inside of something like /usr/local/include/atchops/*.h
)

# add MbedTLS dependencies to `atchops`
target_link_libraries(atchops PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)

# #########################################################
# 4. Install atchops
# doing `make install` or `cmake --build build --target install` (<- recommended) will run all this stuff below
# (this stuff is pretty much analogous to doing something like dart pub add)
# #########################################################

# Installs headers to /usr/local/include/atchops/*.h
install(
    DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # install goes to: /usr/local/include/atchops/*.h
)

# Tells `atchops-config.cmake` where to find mbedtls stuff
install(
    TARGETS ${PROJECT_NAME} mbedtls mbedcrypto mbedx509
    EXPORT ${PROJECT_NAME}-config
)

install(
    EXPORT ${PROJECT_NAME}-config
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} # install goes to: /usr/local/lib/cmake/atchops/atchops-config.cmake
)