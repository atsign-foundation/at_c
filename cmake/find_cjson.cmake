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
      PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_LIST_DIR}/cjson.patch
    )
  endif()
  FetchContent_MakeAvailable(cjson)
  install(TARGETS cjson)
endif()
