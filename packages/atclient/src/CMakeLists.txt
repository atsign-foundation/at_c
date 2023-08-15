if(ESP_PLATFORM)
  message(STATUS "BUILDING AT_CLIENT COMPONENT")

  FILE(GLOB_RECURSE sources ${CMAKE_CURRENT_LIST_DIR}/*.*)

  idf_component_register(
    SRCS ${sources}
    INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/include
    REQUIRES mbedtls
  )

  add_custom_command(
    TARGET ${COMPONENT_LIB}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}> ${CMAKE_SOURCE_DIR}/lib/esp32_espidf/lib${COMPONENT_NAME}.a
    COMMENT "Copying built archive file and header to lib/esp32_espidf directory..."
  )

endif()

