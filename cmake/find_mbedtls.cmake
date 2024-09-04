# This installs the targets mbedtls mbedx509 mbedcrypto everest p256m

# Configurable variables
option(ENABLE_TESTING "Enable MbedTLS tests" OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set

message(STATUS "[MbedTLS] fetching package...")
include(FetchContent)
fetchcontent_declare(
  MbedTLS
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.1/mbedtls-3.6.1.tar.bz2
  URL_HASH
    SHA256=fc8bef0991b43629b7e5319de6f34f13359011105e08e3e16eed3a9fe6ffd3a3 # hash for v3.6.1 .tar.bz2 release source code
  # FIND_PACKAGE_ARGS QUIET CONFIG
)
fetchcontent_makeavailable(MbedTLS)
install(
  TARGETS mbedtls mbedx509 mbedcrypto everest p256m
)
