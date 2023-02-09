FILE(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/src/at_client/*.*)

idf_component_register(
  SRCS ${sources}
  INCLUDE_DIRS "../../include"
  REQUIRES mbedtls
)

add_custom_command(
  TARGET ${COMPONENT_LIB}
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}> ${CMAKE_SOURCE_DIR}/lib/esp32/
  COMMENT "Copying built archive file and header to lib/esp32 directory..."
)
