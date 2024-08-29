idf_component_register(
    SRCS "main.c"
    REQUIRES spi_flash nvs_flash app_update
    INCLUDE_DIRS "../include"
)

set(LIBRARY_PATH ${CMAKE_CURRENT_LIST_DIR}/../lib)

add_library(atclient STATIC IMPORTED)
set_target_properties(atclient PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libatclient.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE atclient)

add_library(atchops STATIC IMPORTED)
set_target_properties(atchops PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libatchops.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE atchops)

add_library(atlogger STATIC IMPORTED)
set_target_properties(atlogger PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libatlogger.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE atlogger)
