
option(RUN_NOCI_TESTS "Run noci tests" OFF)

if(RUN_NOCI_TESTS)
    file(GLOB_RECURSE files ${CMAKE_CURRENT_LIST_DIR}/noci_*.c)
    set(CTEST_OUTPUT_ON_FAILURE TRUE)
else()
    file(GLOB_RECURSE files ${CMAKE_CURRENT_LIST_DIR}/test_*.c)
endif()

foreach(file ${files})
    # ${filename} - without `.c`
    get_filename_component(filename ${file} NAME_WE)

    add_executable(${filename} ${file})
    target_link_libraries(${filename} PRIVATE atclient)
    add_test(NAME ${filename} COMMAND $<TARGET_FILE:${filename}>)
    
endforeach()