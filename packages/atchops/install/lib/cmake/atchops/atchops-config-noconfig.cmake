#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "atchops" for configuration ""
set_property(TARGET atchops APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(atchops PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libatchops.a"
  )

list(APPEND _cmake_import_check_targets atchops )
list(APPEND _cmake_import_check_files_for_atchops "${_IMPORT_PREFIX}/lib/libatchops.a" )

# Import target "mbedtls" for configuration ""
set_property(TARGET mbedtls APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(mbedtls PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libmbedtls.a"
  )

list(APPEND _cmake_import_check_targets mbedtls )
list(APPEND _cmake_import_check_files_for_mbedtls "${_IMPORT_PREFIX}/lib/libmbedtls.a" )

# Import target "mbedcrypto" for configuration ""
set_property(TARGET mbedcrypto APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(mbedcrypto PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libmbedcrypto.a"
  )

list(APPEND _cmake_import_check_targets mbedcrypto )
list(APPEND _cmake_import_check_files_for_mbedcrypto "${_IMPORT_PREFIX}/lib/libmbedcrypto.a" )

# Import target "mbedx509" for configuration ""
set_property(TARGET mbedx509 APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(mbedx509 PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libmbedx509.a"
  )

list(APPEND _cmake_import_check_targets mbedx509 )
list(APPEND _cmake_import_check_files_for_mbedx509 "${_IMPORT_PREFIX}/lib/libmbedx509.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
