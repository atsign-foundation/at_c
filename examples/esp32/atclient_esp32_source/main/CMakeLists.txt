idf_component_register(
    SRCS "main.c"
    REQUIRES spi_flash nvs_flash app_update atclient atchops atlogger
    INCLUDE_DIRS "../include"
)

set(LIBRARY_DIR ${CMAKE_CURRENT_LIST_DIR}/../lib)

add_library(uuid4 STATIC IMPORTED)
set_target_properties(uuid4 PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libuuid4-static.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE uuid4)