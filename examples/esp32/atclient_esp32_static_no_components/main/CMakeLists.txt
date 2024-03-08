idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "atchops/include" "atclient/include" "."
    REQUIRES mbedtls
)

add_prebuilt_library(atchops "${CMAKE_CURRENT_LIST_DIR}/atchops/lib/libatchops.a" REQUIRES mbedtls)
target_link_libraries(${COMPONENT_LIB} INTERFACE atchops)

add_prebuilt_library(atclient "${CMAKE_CURRENT_LIST_DIR}/atclient/lib/libatclient.a" REQUIRES mbedtls atchops)
target_link_libraries(${COMPONENT_LIB} INTERFACE atclient)