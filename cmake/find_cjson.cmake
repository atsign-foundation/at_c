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
      URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.19.zip
      URL_HASH
        SHA256=83fb7750db0601dca735868b8fb1da1318da2d2a1331a9a7da923cb891d26ea9 # hash for v1.7.19 .zip release source code
      PATCH_COMMAND /bin/sh ${CMAKE_CURRENT_LIST_DIR}/cjson-patch.sh
    )
  endif()
  FetchContent_MakeAvailable(cjson)
  install(TARGETS cjson)
endif()
