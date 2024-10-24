# This installs the target cjson
# Configurable variables
set(ARGP_BUILD_SHARED_LIBS OFF CACHE BOOL "Build argp shared libraries")
option(ENABLE_ARGP_TEST "Enable tests for cjson" OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

message(STATUS "[Argp] fetching package...")
include(FetchContent)

FetchContent_Declare(
        argp
        URL https://github.com/jmhodges/argp-standalone

#        URL_HASH
#        SHA256=51f3b07aece8d1786e74b951fd92556506586cb36670741b6bfb79bf5d484216 # hash for v1.7.17 .zip release source code
        # FIND_PACKAGE_ARGS 1.7.17 QUIET CONFIG
)

FetchContent_MakeAvailable(argp)
install(TARGETS argp)