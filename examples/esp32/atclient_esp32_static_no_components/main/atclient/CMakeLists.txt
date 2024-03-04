# register this directory as a component
idf_component_register()

add_prebuilt_library(atclient ${CMAKE_CURRENT_LIST_DIR}/lib/libatclient.a REQUIRES mbedtls)

target_include_directories(atclient INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(${COMPONENT_LIB} INTERFACE atclient) # add it to the component library