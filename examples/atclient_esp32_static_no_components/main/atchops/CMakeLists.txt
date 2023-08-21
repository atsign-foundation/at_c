# register this directory as a component
idf_component_register()

add_prebuilt_library(atchops ${CMAKE_CURRENT_LIST_DIR}/lib/libatchops.a REQUIRES mbedtls)

target_include_directories(atchops INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(${COMPONENT_LIB} INTERFACE atchops) # add it to the component library