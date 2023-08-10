cmake_minimum_required(VERSION 3.19)

project(
	atclient
	VERSION 0.0.1
	DESCRIPTION "Atsign technolgoy client library"
	HOMEPAGE_URL https://atsign.com
	LANGUAGES C
)

# #########################################################
# 0. Variables - you are free to edit anything in this step
# #########################################################

# apparently globs are bad practice, manually add your src files here
set(atclient_srcs
	${CMAKE_CURRENT_LIST_DIR}/src/at_logger.c
	${CMAKE_CURRENT_LIST_DIR}/src/atkeys_filereader.c
	${CMAKE_CURRENT_LIST_DIR}/src/connection.c
)

set(atclient_include_dir
	${CMAKE_CURRENT_LIST_DIR}/include # we do not include nested folder here because we want client to include them like `#include "atclient/xyz.h"
)


# #########################################################
# 0b. Build atchops locally or use already installed atchops
# #########################################################

option(BUILD_LOCAL_ATCHOPS "Build Local ATCHOPS" ON) # can use it like `cmake -S . -B build -DBUILD_LOCAL_ATCHOPS=OFF` to not rebuild atchops everytime
set(atchops_src_dir ${CMAKE_CURRENT_LIST_DIR}/../atchops) # relative to CMakeLists.txt

message(STATUS "Building Local ATCHOPS: ${BUILD_LOCAL_ATCHOPS} from DIR: ${atchops_src_dir}")

# #########################################################
# 1. Include stuff
# #########################################################

# FetchContent is a CMake v3.11+ module that downloads content at configure time
include(FetchContent)

# Difference between FetchContent and ExternalProject: https://cmake.org/cmake/help/latest/module/FetchContent.html#id6

# ${CMAKE_INSTALL_*} variables are defined in GNUInstallDirs and changes according to OS. E.g. on Linux & MacOS, ${CMAKE_INSTALL_LIBDIR} is /usr/local/lib, but on Windows it may be C:\Program Files\atchops\lib
include(GNUInstallDirs)

# #########################################################
# 2A. Get MbedTLS::mbedtls
# #########################################################
FetchContent_Declare(
	MbedTLS
	URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
	URL_HASH SHA256=a420fcf7103e54e775c383e3751729b8fb2dcd087f6165befd13f28315f754f5 # hash for v3.4.1 .tar.gz release source code
)

FetchContent_MakeAvailable(MbedTLS) # ensures named dependencies have been populated

# MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx50 are now available via MbedTLS namespace
message(STATUS "Successfully fetched MbedTLS v3.4.1")

# #########################################################
# 2B. Get atchops::atchops
# #########################################################

# if(BUILD_LOCAL_ATCHOPS)
# 	execute_process(
# 		COMMAND rm -f build/CMakeCache.txt
# 		WORKING_DIRECTORY ${atchops_src_dir}
# 	)

# 	execute_process(
# 		COMMAND cmake -S . -B build
# 		WORKING_DIRECTORY ${atchops_src_dir}
# 	)

# 	execute_process(
# 		COMMAND sudo cmake --build build --target install
# 		WORKING_DIRECTORY ${atchops_src_dir}
# 	)
# endif()

# find_package(atchops REQUIRED CONFIG)

FetchContent_Declare(
	atchops
	SOURCE_DIR ${atchops_src_dir}
)

FetchContent_MakeAvailable(atchops) # ensures named dependencies have been populated



# atchops::atchops is now available
message(STATUS "Successfully found `atchops` package")

# #########################################################
# 3. Create atclient library
# #########################################################
add_library(${PROJECT_NAME} STATIC ${atclient_srcs})

target_link_libraries(${PROJECT_NAME}
	PUBLIC atchops
	PUBLIC MbedTLS::mbedtls
)

target_include_directories(${PROJECT_NAME} PUBLIC
	$<BUILD_INTERFACE:${atclient_include_dir}>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# #########################################################
# 4. Install atclient library
# This step configures running `cmake --build build --target install` (which is the same thing as `make install`)
# #########################################################

# install atclient library to /usr/local/lib/libatclient.a
install(
	TARGETS ${PROJECT_NAME} atchops mbedtls mbedx509 mbedcrypto
	EXPORT ${PROJECT_NAME}-config
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# put everything inside of include/atclient into /usr/local/include/atclient
install(
	DIRECTORY ${atclient_include_dir}/${PROJECT_NAME}
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# exports atclient-config.cmake to /usr/local/lib/cmake/atclient/atclient-config.cmake
install(
	EXPORT ${PROJECT_NAME}-config
	NAMESPACE ${PROJECT_NAME}::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
	FILE ${PROJECT_NAME}-config.cmake
)

# #########################################################
# #########################################################
# #########################################################
# Old CMakeLists.txt
# #########################################################
# #########################################################
# #########################################################

# cmake_minimum_required(VERSION 3.19)

# option(BUILD_ESP_IDF "Build for ESP-IDF" OFF)
# option(BUILD_ARDUINO "Build for Arduino" OFF)
# option(BUILD_MBEDTLS "Build for mbedTLS" OFF)

# if(BUILD_ESP_IDF) # build as an ESP-IDF components
# add_compile_definitions(BUILD_ESP_IDF)
# message(STATUS "BUILDING FOR ESP-IDF")
# set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/targets/esp32_espidf)
# set(COMPONENTS at_client at_chops esp32_espidf)
# include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# endif()

# project(
# at_client
# VERSION 1.0.0
# DESCRIPTION "The at_client implemented in C"
# HOMEPAGE_URL https://atsign.com
# LANGUAGES C
# )

# if(NOT BUILD_ESP_IDF) # build for other platforms (Arduino or MbedTLS)

# # build libraries

# if(BUILD_MBEDTLS)
# add_compile_definitions(BUILD_MBEDTLS)
# message(STATUS "BUILDING FOR MBEDTLS")
# add_subdirectory(deps/mbedtls)
# endif()

# if(BUILD_ARDUINO)
# add_compile_definitions(BUILD_ARDUINO)
# message(STATUS "BUILDING FOR ARDUINO")
# include(${CMAKE_CURRENT_SOURCE_DIR}/deps/Arduino-CMake-Toolchain/Arduino-toolchain.cmake)
# endif()

# # setup at_client library

# FILE(GLOB_RECURSE at_client_sources ${CMAKE_SOURCE_DIR}/src/at_client/*.*)
# add_library(at_client STATIC ${at_client_sources})

# # setup at_chops library
# FILE(GLOB_RECURSE at_chops_sources ${CMAKE_SOURCE_DIR}/src/at_chops/*.*)
# add_library(at_chops STATIC ${at_chops_sources})

# set_target_properties(at_client PROPERTIES LINKER_LANGUAGE C)
# set(CMAKE_C_STANDARD 99)
# target_compile_features(at_client PRIVATE c_std_99)

# target_include_directories(at_chops PUBLIC ${CMAKE_SOURCE_DIR}/include)
# target_include_directories(at_chops PUBLIC ${CMAKE_SOURCE_DIR}/include/at_chops)
# target_include_directories(at_client PUBLIC ${CMAKE_SOURCE_DIR}/include)
# target_include_directories(at_client PUBLIC ${CMAKE_SOURCE_DIR}/include/at_client)

# # link libraries
# if(BUILD_MBEDTLS)
# target_link_libraries(at_chops PUBLIC mbedtls)
# target_link_libraries(at_chops PUBLIC mbedx509)
# target_link_libraries(at_chops PUBLIC mbedcrypto)
# endif()

# if(BUILD_ARDUINO)
# target_link_arduino_libraries(at_chops PRIVATE core)
# endif()

# target_link_libraries(at_client PRIVATE at_chops)

# # tests
# # enable_testing()

# # add_executable(test_base64 test/test_base64.c)
# # target_link_libraries(test_base64 PRIVATE at_client)
# # add_test(
# #   NAME BASE64
# #   COMMAND $<TARGET_FILE:test_base64>)

# # add_executable(test_aes_ctr test/test_aes_ctr.c)
# # target_link_libraries(test_aes_ctr PRIVATE at_client)
# # add_test(
# #   NAME AES_CTR
# #   COMMAND $<TARGET_FILE:test_aes_ctr>
# #   )

# # add_executable(test_rsapublicpopulate test/test_rsapublicpopulate.c)
# # target_link_libraries(test_rsapublicpopulate PRIVATE at_client)
# # add_test(
# #   NAME RSA_PUBLICPOPULATE
# #   COMMAND $<TARGET_FILE:test_rsapublicpopulate>)

# # add_executable(test_rsaprivatepopulate test/test_rsaprivatepopulate.c)
# # target_link_libraries(test_rsaprivatepopulate PRIVATE at_client)
# # add_test(
# #   NAME RSA_PRIVATEPOPULATE
# #   COMMAND $<TARGET_FILE:test_rsaprivatepopulate>)

# # add_executable(test_rsasign test/test_rsasign.c)
# # target_link_libraries(test_rsasign PRIVATE at_client)
# # add_test(
# #   NAME RSA_SIGN
# #   COMMAND $<TARGET_FILE:test_rsasign>)

# # add_executable(test_rsaencrypt test/test_rsaencrypt.c)
# # target_link_libraries(test_rsaencrypt PRIVATE at_client)
# # add_test(
# #   NAME RSA_ENCRYPT
# #   COMMAND $<TARGET_FILE:test_rsaencrypt>)

# # add_executable(test_rsadecrypt test/test_rsadecrypt.c)
# # target_link_libraries(test_rsadecrypt PRIVATE at_client)
# # add_test(
# #   NAME RSA_DECRYPT
# #   COMMAND $<TARGET_FILE:test_rsadecrypt>)

# # add_executable(test_connection test/test_connection.c)
# # target_link_libraries(test_connection PRIVATE at_client)
# # add_test(
# #   NAME CONNECTION
# #   COMMAND $<TARGET_FILE:test_connection>)

# # compiler flags
# target_compile_options(at_client # https://vladiant.github.io/blog/2021/08/14/cpp-compiler-flags
# PRIVATE -Wall -Wextra -Wuninitialized -Wpedantic -Wshadow -Wmissing-include-dirs -Wundef -Winvalid-pch # Essentials
# PRIVATE -Winit-self -Wswitch-enum -Wswitch-default -Wformat=2 -Wformat-nonliteral -Wformat-security -Wformat-y2k # Control flow
# PRIVATE -Wdouble-promotion -Wfloat-equal -Wpointer-arith # Arithmetic
# PRIVATE -Wstrict-overflow=5 -Wcast-qual -Wcast-align -Wconversion -Wpacked # Casting
# PRIVATE -Wstrict-aliasing -fstrict-aliasing -Wredundant-decls -Wmissing-declarations -Wmissing-field-initializers # Sanitizing
# PRIVATE -Wwrite-strings -Wstack-protector -fstack-protector -Wpadded -Winline -Wdisabled-optimization # Security
# PRIVATE -Waggregate-return -Wbad-function-cast -Wc++-compat # C specific
# )
# endif()
