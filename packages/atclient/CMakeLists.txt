cmake_minimum_required(VERSION 3.19)

# # # #######################################################
# 1. Variables - you are free to edit anything in this step
# # # #######################################################

# 1a. Manually add your src files here
# globs are known as bad practice, so we do not use them here
set(atclient_srcs
 ${CMAKE_CURRENT_LIST_DIR}/src/atbytes.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atclient.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atkey.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atkeys.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atkeysfile.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atlogger.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atsign.c
 ${CMAKE_CURRENT_LIST_DIR}/src/atstr.c
 ${CMAKE_CURRENT_LIST_DIR}/src/connection.c
 ${CMAKE_CURRENT_LIST_DIR}/src/metadata.c
 ${CMAKE_CURRENT_LIST_DIR}/src/monitor.c
 ${CMAKE_CURRENT_LIST_DIR}/src/notify.c
 ${CMAKE_CURRENT_LIST_DIR}/src/stringutils.c
)

# 1b. Manually add your include directories here
set(
  ATCLIENT_INCLUDE_DIR
  ${CMAKE_CURRENT_LIST_DIR}/include # we do not include nested folder here because we want client to include them like ` #include "atclient/xyz.h"
)

# 1c. atchops package directory
set(ATCHOPS_DIR ${CMAKE_CURRENT_LIST_DIR}/../atchops)

# 1d. Set compile definitions
# you may set any of these flags in the CMake configuration step via: `-DATCLIENT_BUILD_TESTS=ON` (example: `cmake -S . -B build -DATCLIENT_BUILD_TESTS=OFF)
# or you may edit the defaults here
option(ATCLIENT_BUILD_TESTS "Build atclient tests" OFF) # ON=>builds tests by running the tests/CMakeLists.txt file and generates a `tests/` folder in the build directory where `ctest` can be ran in that directory, OFF=>does not build `tests/`
option(ATCLIENT_EXPORT_ATLOGGER "Export atlogger as a standalone library" OFF) # ON=>builds tests by running the tests/CMakeLists.txt file and generates a `tests/` folder in the build directory where `ctest` can be ran in that directory, OFF=>does not build `tests/`

# # # #######################################################
# 2. Build for ESP32 or Desktop?
# # # #######################################################

# 2a. Build for ESP32
if(ESP_PLATFORM)
  # Run special CMake commands for ESP32
  idf_component_register(
  SRCS ${atclient_srcs}
  INCLUDE_DIRS ${ATCLIENT_INCLUDE_DIR}
  REQUIRES mbedtls atchops
  )

  # Copy header files to include directory and libraries to lib directory
  add_custom_command(
    TARGET ${COMPONENT_LIB}
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${ATCLIENT_INCLUDE_DIR}
      ${CMAKE_SOURCE_DIR}/include
    COMMAND
      ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}>
      ${CMAKE_SOURCE_DIR}/lib/lib${COMPONENT_NAME}.a
    COMMENT "Copying built archive file and header to lib directory..."
  )
endif()

project(
  atclient
  VERSION 0.0.1
  DESCRIPTION "Atsign technology client library"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

set(CMAKE_C_STANDARD 99)
# 2b. Build for Desktop
if(NOT ESP_PLATFORM)
  # # ########################################################
  # 3. Include CMake modules
  # # ########################################################

  # FetchContent is a CMake v3.11+ module that downloads content at configure time
  # Difference between FetchContent and ExternalProject: https://cmake.org/cmake/help/latest/module/FetchContent.html #id6
  include(FetchContent)

  # Contains ${CMAKE_INSTALL_*} variables are defined in GNUInstallDirs and changes according to OS.
  # E.g. on Linux & MacOS, ${CMAKE_INSTALL_LIBDIR} is /usr/local/lib, but on Windows it may be C:\Program Files\atchops\lib
  include(GNUInstallDirs)

  # Determine if atclient is being built as a subproject
  if(NOT DEFINED ATCLIENT_AS_SUBPROJECT)
    set(ATCLIENT_AS_SUBPROJECT ON)

    if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
      set(ATCLIENT_AS_SUBPROJECT OFF)
    endif()
  endif()

  # # ########################################################
  # 4. Set CMake policies
  # # ########################################################

  # Ensures that non-deprecated behaviour is used in ExternalProject_Add and FetchContent modules
  # https://cmake.org/cmake/help/latest/policy/CMP0135.html
  cmake_policy(SET CMP0135 NEW)

  # # ########################################################
  # 5. Dependencies
  # # ########################################################

  # # ########################################################
  # 5A. atchops
  # # ########################################################
  find_package(atchops QUIET)

  if(NOT atchops_FOUND)
    message(
      STATUS
      "[ATCLIENT] atchops not found, fetching from local repository.."
    )
    fetchcontent_declare(atchops SOURCE_DIR ${ATCHOPS_DIR})
    list(APPEND ATCLIENT_TARGETS_TO_INSTALL atchops uuid4-static) # since we've fetched it, we have to install the targets
    list(APPEND ATCLIENT_MAKE_AVAILABLE atchops) # we have to make it available later on with FetchContent_MakeAvailable
  else()
    message(STATUS "[ATCLIENT] atchops found package..")
  endif()

  # # ########################################################
  # 5B. MbedTLS
  # # ########################################################
  find_package(MbedTLS QUIET)

  if(NOT MbedTLS_FOUND)
    message(STATUS "[ATCLIENT] MbedTLS not found, fetching from GitHub..")
    fetchcontent_declare(
      MbedTLS
      URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.5.1.zip
      URL_HASH
        SHA256=959a492721ba036afc21f04d1836d874f93ac124cf47cf62c9bcd3a753e49bdb # hash for v3.5.1 .zip release source code
    )
    list(
      APPEND
      ATCLIENT_TARGETS_TO_INSTALL
      mbedtls
      mbedx509
      mbedcrypto
      p256m
      everest
    ) # since we've fetched it, we have to install the targets
    list(APPEND ATCLIENT_MAKE_AVAILABLE MbedTLS) # we have to make it available later on with FetchContent_MakeAvailable
  else()
    message(STATUS "[ATCLIENT] MbedTLS found package..")
  endif()

  if(ATCLIENT_BUILD_TESTS)
    message(STATUS "[MbedTLS] enabling tests" ])
    set(ENABLE_TESTING ON)
  else()
    message(STATUS "[MbedTLS] disabling tests" ])
    set(ENABLE_TESTING OFF)
  endif()

  # # ########################################################
  # 5C. cJSON
  # # ########################################################
  find_package(cjson QUIET)

  if(NOT cjson_FOUND)
    message(STATUS "[ATCLIENT] cJSON not found, fetching from GitHub..")
    fetchcontent_declare(
      cjson
      URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.17.zip
      URL_HASH
        SHA256=51f3b07aece8d1786e74b951fd92556506586cb36670741b6bfb79bf5d484216 # hash for v1.7.17 .zip release source code
    )

    list(APPEND ATCLIENT_TARGETS_TO_INSTALL cjson) # since we've fetched it, we have to install it
    set(CJSON_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(CJSON_OVERRIDE_BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
    set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
    add_compile_options(-fPIC)
    fetchcontent_makeavailable(cjson)
  else()
    message(STATUS "[ATCHOPS] cJSON found package..")
  endif()

  if(ATCLIENT_MAKE_AVAILABLE)
    fetchcontent_makeavailable(${ATCLIENT_MAKE_AVAILABLE})
  endif()

  # # ########################################################
  # 5D. Create atlogger library
  # - atlogger header files are installed to `/usr/local/include/atlogger`
  # - atlogger library is automatically linked as part of atclient library (when you install atclient, it already includes atlogger)
  # - atlogger library is only exported as a standalone library if ATCLIENT_EXPORT_ATLOGGER is set to ON
  # # ########################################################
  if(ATCLIENT_EXPORT_ATLOGGER)
    add_library(atlogger STATIC ${CMAKE_CURRENT_LIST_DIR}/src/atlogger.c)
    add_library(${PROJECT_NAME}::atlogger ALIAS atlogger)

    target_include_directories(
      atlogger
      PUBLIC
        $<BUILD_INTERFACE:${ATCLIENT_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/atlogger>
    )

    list(APPEND ATCLIENT_TARGETS_TO_INSTALL atlogger) # install atlogger
  endif()

  # # ########################################################
  # 6. Create atclient library
  # # ########################################################

  # Create `atclient` target
  add_library(${PROJECT_NAME} STATIC ${atclient_srcs})
  add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

  # Manually add header file
  configure_file(
    ${cjson_SOURCE_DIR}/cJSON.h
    ${CMAKE_BINARY_DIR}/include/cjson/cJSON.h
  )

  # Set include directories for atclient target
  target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
      $<BUILD_INTERFACE:${ATCLIENT_INCLUDE_DIR}>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  # atclient depends on cjson, so the latter must be built first
  add_dependencies(atclient cjson)

  # Link libraries to atclient target
  target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC atchops::atchops MbedTLS::mbedtls MbedTLS::mbedx509 cjson
  )

  install(
    DIRECTORY ${ATCLIENT_INCLUDE_DIR}/atlogger
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # # ########################################################
  # 7. Install atclient library
  # This step configures running `cmake --build build --target install` (which is the same thing as `make install`)
  # This work also helps other CMake projects use `find_package(atclient)` to find our library, once installed.
  # # ########################################################

  # exports atclient-config.cmake to /usr/local/lib/cmake/atclient/atclient-config.cmake
  list(APPEND ATCLIENT_TARGETS_TO_INSTALL ${PROJECT_NAME}) # install atclient

  # install atclient library to /usr/local/lib/libatclient.a
  foreach(target ${ATCLIENT_TARGETS_TO_INSTALL})
    message(STATUS "[ATCLIENT] Installing ${target}..")
    install(
      TARGETS ${target}
      EXPORT ${PROJECT_NAME}-config
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
  endforeach()

  # Copy all headerfiles from `include/atclient` into `/usr/local/include/atclient`
  install(
    DIRECTORY ${ATCLIENT_INCLUDE_DIR}/${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # # ########################################################
  # 9. Export in case people use us in a subdirectory
  # Allows other Cmake projects to do `add_subdirectory(/path/to/atclient)` and then `target_link_libraries(their_target atclient::atclient)`
  # # ########################################################
  if(NOT ATCLIENT_AS_SUBPROJECT) # if it is not a sub project, we should install the -config.cmake
    export(
      EXPORT ${PROJECT_NAME}-config
      NAMESPACE ${PROJECT_NAME}::
      FILE ${PROJECT_NAME}-config.cmake
    )

    # install the config to /usr/local/lib/cmake/atclient/atclient-config.cmake
    install(
      EXPORT ${PROJECT_NAME}-config
      NAMESPACE ${PROJECT_NAME}::
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
      FILE ${PROJECT_NAME}-config.cmake
    )

    export(PACKAGE ${PROJECT_NAME})
  endif()

  # # ########################################################
  # 10. Add tests
  # Run the tests via cd build && make all && cd tests && ctest
  # configure with -DATCLIENT_BUILD_TESTS=ON
  # # ########################################################
  if(ATCLIENT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests)
  endif()
endif()
