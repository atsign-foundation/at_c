# This installs the target cjson
# Configurable variables
set(CJSON_BUILD_SHARED_LIBS OFF CACHE BOOL "Build cjson shared libraries")
set(ENABLE_CJSON_TEST OFF CACHE BOOL "Enable cjson tests")
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

message(STATUS "[cjson] fetching package...")
include(FetchContent)

fetchcontent_declare(
  cjson
  URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.17.zip
  URL_HASH
    SHA256=51f3b07aece8d1786e74b951fd92556506586cb36670741b6bfb79bf5d484216 # hash for v1.7.17 .zip release source code
  # FIND_PACKAGE_ARGS 1.7.17 QUIET CONFIG
)

fetchcontent_makeavailable(cjson)
install(TARGETS cjson)
configure_file(
  ${cjson_SOURCE_DIR}/cJSON.h
  ${CMAKE_BINARY_DIR}/include/cjson/cJSON.h
)
