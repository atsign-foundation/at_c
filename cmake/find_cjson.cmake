option(ATSDK_CJSON_PATH "Local cJSON path" OFF)
option(ENABLE_CJSON_TEST "Test cJSON" OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

if(NOT TARGET cjson)
  # This installs the target cjson
  # Configurable variables

  message(STATUS "[cJSON] fetching package...")
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
      URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.17.zip
      URL_HASH
        SHA256=51f3b07aece8d1786e74b951fd92556506586cb36670741b6bfb79bf5d484216 # hash for v1.7.17 .zip release source code
      # FIND_PACKAGE_ARGS 1.7.17 QUIET CONFIG
    )
  endif()
  FetchContent_MakeAvailable(cjson)
  install(TARGETS cjson)
endif()
