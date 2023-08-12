
# loop through every .c file in this directory
file(GLOB_RECURSE files ${CMAKE_CURRENT_LIST_DIR}/test_*.c)
foreach(file ${files})
    # ${filename} - without `.c`
    get_filename_component(filename ${file} NAME)
    string(REPLACE ".c" "" filename ${filename})

    add_executable(${filename} ${file})
    target_link_libraries(${filename} PRIVATE atchops)
    if(WIN32)
        # add_test(NAME ${filename} COMMAND "$<TARGET_FILE:${filename}>")
        add_test(NAME ${filename} COMMAND ${CMAKE_CURRENT_SOURCE_DIR}\\$<TARGET_FILE:${filename}>.exe)
    elseif(UNIX)
        add_test(NAME ${filename} COMMAND $<TARGET_FILE:${filename}>)
    endif()
endforeach()
