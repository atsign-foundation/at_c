
# # targets
# # -------
# # cJSON::cjson-static
# # cJSON::cjson-shared

# include(GNUInstallDirs)

# set(CJSON_STATIC_LIB cjson-static)
# set(CJSON_SHARED_LIB cjson-shared)

# set(CJSON_SOURCES
#     ${CMAKE_CURRENT_LIST_DIR}/src/cJSON.c
# )

# set(CJSON_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# add_library(${CJSON_STATIC_LIB} STATIC
#     ${CJSON_SOURCES}
# )

# add_library(${CJSON_SHARED_LIB} SHARED
#     ${CJSON_SOURCES}
# )

# target_include_directories(${CJSON_STATIC_LIB} PUBLIC
#     $<BUILD_INTERFACE:${CJSON_INCLUDE_DIR}>
#     $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
# )

# target_include_directories(${CJSON_SHARED_LIB} PUBLIC
#     $<BUILD_INTERFACE:${CJSON_INCLUDE_DIR}>
#     $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
# )

# add_library(cJSON::cjson-static ALIAS ${CJSON_STATIC_LIB})
# add_library(cJSON::cjson-shared ALIAS ${CJSON_SHARED_LIB})

