# include(FindPackageHandleStandardArgs)
# find_package(uuid4 QUIET CONFIG)
# find_package_handle_standard_args(uuid4 CONFIG_MODE)

if(uuid4_FOUND AND TARGET uuid4::uuid4-static OR TARGET uuid4-static)
  message(STATUS "[uuid4] package found locally")
else()
  message(STATUS "[uuid4] package not found, fetching from GitHub..")
  include(FetchContent)
  fetchcontent_declare(
    uuid4
    URL
      https://github.com/atsign-foundation/uuid4/releases/download/v1.0.2/uuid4-v1.0.2.zip
    URL_HASH MD5=797b23ad01c967517da2c9594dccecd1
  )
  fetchcontent_makeavailable(uuid4)
  install(TARGETS uuid4-static)
endif()
