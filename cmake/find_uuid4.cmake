# This installs the target uuid4-static

# Configuration options
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

message(STATUS "[uuid4] fetching package...")
include(FetchContent)
fetchcontent_declare(
  uuid4
  URL
    https://github.com/atsign-foundation/uuid4/releases/download/v1.0.2/uuid4-v1.0.2.zip
  URL_HASH MD5=797b23ad01c967517da2c9594dccecd1
  # FIND_PACKAGE_ARGS QUIET CONFIG
)
fetchcontent_makeavailable(uuid4)
install(TARGETS uuid4-static)
