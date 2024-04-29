# check if subdirectory
if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    set(FUNCTIONAL_TESTS_LIB_SUBDIRECTORY FALSE)
else()
    set(FUNCTIONAL_TESTS_LIB_SUBDIRECTORY TRUE)
endif()

set(FUNCTIONAL_TESTS_LIB_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/config.c
)

set(FUNCTIONAL_TESTS_LIB_INCLUDE_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/include
)

add_library(functional_tests_lib STATIC
    ${FUNCTIONAL_TESTS_LIB_SOURCES}
)

target_include_directories(functional_tests_lib
    PUBLIC
        ${FUNCTIONAL_TESTS_LIB_INCLUDE_DIRS}
)

add_library(atsdk::functional_tests_lib ALIAS functional_tests_lib)
