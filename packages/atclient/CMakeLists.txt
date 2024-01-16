cmake_minimum_required(VERSION 3.19)

# #########################################################
# 0. Variables - you are free to edit anything in this step
# #########################################################

# apparently globs are bad practice, manually add your src files here
set(atclient_srcs
	${CMAKE_CURRENT_LIST_DIR}/src/atclient.c
	${CMAKE_CURRENT_LIST_DIR}/src/atkey.c
	${CMAKE_CURRENT_LIST_DIR}/src/atkeys.c
	${CMAKE_CURRENT_LIST_DIR}/src/atkeysfile.c
	${CMAKE_CURRENT_LIST_DIR}/src/atlogger.c
	${CMAKE_CURRENT_LIST_DIR}/src/atstr.c
	${CMAKE_CURRENT_LIST_DIR}/src/connection.c
	${CMAKE_CURRENT_LIST_DIR}/src/metadata.c
)

set(atclient_include_dir
	${CMAKE_CURRENT_LIST_DIR}/include # we do not include nested folder here because we want client to include them like `#include "atclient/xyz.h"
)

if(ESP_PLATFORM)
	idf_component_register(
		SRCS ${atclient_srcs}
		INCLUDE_DIRS ${atclient_include_dir}
		REQUIRES mbedtls atchops
	)
	add_custom_command(
		TARGET ${COMPONENT_LIB}
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_directory ${atclient_include_dir} ${CMAKE_SOURCE_DIR}/include
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}> ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
		COMMENT "Copying built archive file and header to lib directory..."
	)
endif()

project(
	atclient
	VERSION 0.0.1
	DESCRIPTION "Atsign technolgoy client library"
	HOMEPAGE_URL https://atsign.com
	LANGUAGES C
)

if(NOT ESP_PLATFORM) # build for Desktop
	option(ATCLIENT_BUILD_TESTS "Build atclient tests" OFF)

	option(ATCLIENT_FETCH_ATCHOPS "Use Local ATCHOPS" ON)
	option(ATCLIENT_FETCH_MBEDTLS "Fetch MbedTLS via releases" ON)

	# #########################################################
	# 0b. Build atchops locally or use already installed atchops
	# #########################################################

	# can use during the configuration command
	# example: `cmake -S . -B build -DFETCH_ATCHOPS=OFF` to not rebuild atchops everytime
	if(ATCLIENT_FETCH_ATCHOPS)
		set(atchops_src_dir ${CMAKE_CURRENT_LIST_DIR}/../atchops)
		message(STATUS "Building Local ATCHOPS: ${USE_LOCAL_ATCHOPS} from DIR: ${atchops_src_dir}")
	endif()

	# #########################################################
	# 1. Include stuff
	# #########################################################

	# FetchContent is a CMake v3.11+ module that downloads content at configure time
	include(FetchContent)

	# Difference between FetchContent and ExternalProject: https://cmake.org/cmake/help/latest/module/FetchContent.html#id6

	# ${CMAKE_INSTALL_*} variables are defined in GNUInstallDirs and changes according to OS. E.g. on Linux & MacOS, ${CMAKE_INSTALL_LIBDIR} is /usr/local/lib, but on Windows it may be C:\Program Files\atchops\lib
	include(GNUInstallDirs)

	# https://cmake.org/cmake/help/latest/policy/CMP0135.html
	cmake_policy(SET CMP0135 NEW)

	# #########################################################
	# 2A. Get MbedTLS::mbedtls
	# #########################################################
	if(ATCLIENT_FETCH_MBEDTLS)
		FetchContent_Declare(
			MbedTLS
			URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.1.tar.gz
			URL_HASH SHA256=a420fcf7103e54e775c383e3751729b8fb2dcd087f6165befd13f28315f754f5 # hash for v3.4.1 .tar.gz release source code
		)
		FetchContent_MakeAvailable(MbedTLS) # ensures named dependencies have been populated
		message(STATUS "Successfully fetched MbedTLS")
	else()
		find_package(MbedTLS REQUIRED CONFIG)
		message(STATUS "Successfully found `MbedTLS` package")
	endif()

	# MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx50 are now available via MbedTLS namespace

	# #########################################################
	# 2B. Get atchops
	# #########################################################
	if(ATCLIENT_FETCH_ATCHOPS)
		FetchContent_Declare(
			atchops
			SOURCE_DIR ${atchops_src_dir}
			
		)
		FetchContent_MakeAvailable(atchops) # ensures named dependencies have been populated
		message(STATUS "Successfully fetched `atchops` package")
	else()
		find_package(atchops REQUIRED CONFIG)
		message(STATUS "Successfully found `atchops` package")
	endif()

	# atchops::atchops is now available

	# #########################################################
	# 3. Create atclient library
	# #########################################################
	add_library(${PROJECT_NAME} STATIC ${atclient_srcs})

	target_link_libraries(${PROJECT_NAME}
		PUBLIC MbedTLS::mbedtls MbedTLS::mbedx509 atchops::atchops
	)

	target_include_directories(${PROJECT_NAME} PUBLIC
		$<BUILD_INTERFACE:${atclient_include_dir}>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
	)

	# #########################################################
	# 4. Install atclient library
	# This step configures running `cmake --build build --target install` (which is the same thing as `make install`)
	# #########################################################

	# exports atclient-config.cmake to /usr/local/lib/cmake/atclient/atclient-config.cmake
	set(TARGETS_TO_INSTALL ${PROJECT_NAME}) # install atclient

	if(ATCLIENT_FETCH_ATCHOPS) # if we are fetching atchops, it was not installed, so we do not need to export it
		list(APPEND TARGETS_TO_INSTALL atchops) # install atchops
	endif()

	if(ATCLIENT_FETCH_MBEDTLS) # if we are fetching mbedtls, it was not installed, so we do not need to export it
		list(APPEND TARGETS_TO_INSTALL mbedtls mbedx509 mbedcrypto) # install mbedtls
	endif()

	# install atclient library to /usr/local/lib/libatclient.a
	install(
		TARGETS ${TARGETS_TO_INSTALL}
		EXPORT ${PROJECT_NAME}-config
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)

	# export the config to /usr/local/lib/cmake/atclient/atclient-config.cmake
	install(
		EXPORT ${PROJECT_NAME}-config
		NAMESPACE ${PROJECT_NAME}::
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
		FILE ${PROJECT_NAME}-config.cmake
	)

	install(
		EXPORT ${PROJECT_NAME}-config
		NAMESPACE ${PROJECT_NAME}::
		FILE ${PROJECT_NAME}-targets.cmake # New: Required when writing our own <proj>-config.cmake file
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

	# put everything inside of include/atclient into /usr/local/include/atclient
	install(
		DIRECTORY ${atclient_include_dir}/${PROJECT_NAME}
		DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	)

	# #########################################################
	# 5. Export in case people use us in a subdirectory
	# #########################################################
	export(
		EXPORT ${PROJECT_NAME}-config
		NAMESPACE ${PROJECT_NAME}::
		FILE ${PROJECT_NAME}-config.cmake
	)

	export(
		EXPORT ${PROJECT_NAME}-config
		NAMESPACE ${PROJECT_NAME}::
		FILE ${PROJECT_NAME}-targets.cmake
	)

	export(
		PACKAGE ${PROJECT_NAME}
	)

	add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

	# #########################################################
	# 6. Add tests
	# Run the tests via cd build && make all && cd tests && ctest
	# configure with -DATCLIENT_BUILD_TESTS=ON
	# #########################################################
	if(ATCLIENT_BUILD_TESTS)
		enable_testing()
		add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests)
	endif()

	# #########################################################
	# 7. Build for ESP32
	# #########################################################
	if(ATCLIENT_BUILD_ESPIDF)
		message(STATUS "Building for ESP32")
		set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src)
		include($ENV{IDF_PATH}/tools/cmake/project.cmake)
		add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/src)
	endif()


endif()
