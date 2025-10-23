option(ATSDK_MBEDTLS_PATH "Local mbedtls path" OFF)
option(ENABLE_TESTING "Test mbedtls" OFF)
option(ENABLE_PROGRAMS "Build mbedtls programs" OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE OPT_IN) # only try find_package if FIND_PACKAGE_ARGS is set
set(CMAKE_POLICY_DEFAULT_CMP0077 OLD)

if(ATSDK_USE_SHARED_LIBS)
  return()
endif()

if(NOT TARGET mbedcrypto)
  # This installs the targets mbedtls mbedx509 mbedcrypto everest p256m
  message(STATUS "[MbedTLS] resolving package...")
  include(FetchContent)
  if(ATSDK_MBEDTLS_PATH)
    FetchContent_Declare(
      mbedtls
      SOURCE_DIR
      ${CMAKE_SOURCE_DIR}/${ATSDK_MBEDTLS_PATH}
    )
  else()
    FetchContent_Declare(
      MbedTLS
      URL
        https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2
      URL_HASH
        SHA256=4a11f1777bb95bf4ad96721cac945a26e04bf19f57d905f241fe77ebeddf46d8 # hash for v3.6.5 .tar.bz2 release source code
      # FIND_PACKAGE_ARGS QUIET CONFIG
    )
  endif()
    FetchContent_MakeAvailable(MbedTLS)
    install(
      TARGETS mbedtls mbedx509 mbedcrypto everest p256m
    )
endif()
