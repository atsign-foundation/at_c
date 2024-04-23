# This installs the targets mbedtls mbedx509 mbedcrypto everest p256m

# Configurable variables
set(ENABLE_TESTING OFF CACHE BOOL "Enable MbedTLS tests")

# include(FindPackageHandleStandardArgs)
# find_package(MbedTLS QUIET CONFIG)
# find_package_handle_standard_args(mbedtls CONFIG_MODE)

if(
  MbedTLS_FOUND
  AND TARGET MbedTLS::mbedtls
  AND TARGET MbedTLS::mbedx509
  AND TARGET MbedTLS::mbedcrypto
  AND TARGET everest
  AND TARGET p256m
)
  message(STATUS "[MbedTLS] package found locally")
else()
  message(STATUS "[MbedTLS] package not found, fetching from GitHub..")
  include(FetchContent)
  fetchcontent_declare(
    MbedTLS
    URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.5.1.zip
    URL_HASH
      SHA256=959a492721ba036afc21f04d1836d874f93ac124cf47cf62c9bcd3a753e49bdb # hash for v3.5.1 .zip release source code
  )
  fetchcontent_makeavailable(MbedTLS)
  install(
    TARGETS mbedtls mbedx509 mbedcrypto everest p256m
  )
endif()
