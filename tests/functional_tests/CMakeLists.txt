cmake_minimum_required(VERSION 3.19)
set(CMAKE_C_STANDARD 99)

project(
    functional_tests
    VERSION 0.0.1
    DESCRIPTION "Functional tests for atsdk"
    HOMEPAGE_URL https://atsign.com
    LANGUAGES C
)

find_package(atsdk CONFIG REQUIRED)

enable_testing()

file(GLOB_RECURSE files ${CMAKE_CURRENT_LIST_DIR}/tests/*test_*.c)
foreach(file ${files})
    # ${filename} - without `.c`
    get_filename_component(filename ${file} NAME)
    string(REPLACE ".c" "" filename ${filename})

    add_executable(${filename} ${file})
    target_link_libraries(${filename} PRIVATE atsdk::atclient)
    add_test(NAME ${filename} COMMAND $<TARGET_FILE:${filename}>)
endforeach()
