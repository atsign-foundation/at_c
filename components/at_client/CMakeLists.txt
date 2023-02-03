idf_component_register(SRCS at_client.c
INCLUDE_DIRS "../../include"
REQUIRES mbedtls)

add_custom_command(TARGET ${COMPONENT_LIB}
POST_BUILD
COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${COMPONENT_LIB}> ${CMAKE_SOURCE_DIR}/lib/esp32/
COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/../../include/at_client.h ${CMAKE_SOURCE_DIR}/lib/esp32/include/
COMMENT "Copying built archive file and header to lib/esp32 directory...")
