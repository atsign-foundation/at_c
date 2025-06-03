option(ATSDK_CJSON_PATH "Local cJSON path" OFF)
option(ENABLE_CJSON_TEST "Test cJSON" OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

if(ATSDK_USE_SHARED_LIBS)
  return()
endif()

if(NOT TARGET cjson)
  # This installs the target cjson
  # Configurable variables

  message(STATUS "[cJSON] resolving package...")
  include(FetchContent)
  if(ATSDK_CJSON_PATH)
    FetchContent_Declare(
      cjson
      SOURCE_DIR
      ${CMAKE_SOURCE_DIR}/${ATSDK_CJSON_PATH}
    )
  else()
    FetchContent_Declare(
      cjson
      URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.zip
      URL_HASH
        SHA256=cc6d93cc3b659037c34193ecc7be5a874a18c2ac67b24efe82db6a759b486b5d # hash for v1.7.18 .zip release source code
      # FIND_PACKAGE_ARGS 1.7.17 QUIET CONFIG
      # GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
      # GIT_TAG v1.7.18
      # This PATCH_COMMAND entry performs the following:
      # Replaces the following line in the cJSON CMakeLists.txt:
      # `cmake_minimum_required(VERSION 3.0)`
      # With the line:
      # `cmake_minimum_required(VERSION 3.24)`
      # This allows us to build it with CMake v4
      PATCH_COMMAND bash -c "sed -e '2s/0/24/' -i CMakeLists.txt"
    )
  endif()
  FetchContent_MakeAvailable(cjson)
  install(TARGETS cjson)
endif()
