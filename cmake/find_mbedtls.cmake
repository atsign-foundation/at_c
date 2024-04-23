# This installs the targets mbedtls mbedx509 mbedcrypto everest p256m

# Configurable variables
option(ENABLE_TESTING "Enable MbedTLS tests" OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

message(STATUS "[MbedTLS] fetching package...")
include(FetchContent)
fetchcontent_declare(
  MbedTLS
  URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.5.1.zip
  URL_HASH
    SHA256=959a492721ba036afc21f04d1836d874f93ac124cf47cf62c9bcd3a753e49bdb # hash for v3.5.1 .zip release source code
  # FIND_PACKAGE_ARGS QUIET CONFIG
)
fetchcontent_makeavailable(MbedTLS)
install(
  TARGETS mbedtls mbedx509 mbedcrypto everest p256m
)
