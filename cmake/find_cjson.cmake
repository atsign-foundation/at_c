# This installs the target cjson
# Configurable variables
set(CJSON_BUILD_SHARED_LIBS OFF CACHE BOOL "Build cjson shared libraries")
set(ENABLE_CJSON_TEST OFF CACHE BOOL "Enable cjson tests")

# include(FindPackageHandleStandardArgs)
# find_package(cjson 1.7.17 QUIET CONFIG)
# find_package_handle_standard_args(cjson CONFIG_MODE)

if(cjson_FOUND AND TARGET cjson)
  message(STATUS "[cjson] package found locally")
else()
  message(STATUS "[cjson] package not found, fetching from GitHub..")
  include(FetchContent)
  fetchcontent_declare(
    cjson
    URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.17.zip
    URL_HASH
      SHA256=51f3b07aece8d1786e74b951fd92556506586cb36670741b6bfb79bf5d484216 # hash for v1.7.17 .zip release source code
  )

  fetchcontent_makeavailable(cjson)
  install(TARGETS cjson)
endif()
