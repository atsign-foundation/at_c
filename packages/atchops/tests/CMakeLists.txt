option(FIRST_ATSIGN "First atSign used for all functional tests")
if(${FIRST_ATSIGN})
  add_compile_definitions(FIRST_ATSIGN)
endif()

option(SECOND_ATSIGN "Second atSign for two-way atSign functional tests")
if(${SECOND_ATSIGN})
  add_compile_definitions(SECOND_ATSIGN)
endif()

# loop through every .c file in this directory
file(GLOB_RECURSE files ${CMAKE_CURRENT_LIST_DIR}/test_*.c)

foreach(file ${files})
  # ${filename} - without `.c`
  get_filename_component(filename ${file} NAME)
  string(REPLACE ".c" "" filename ${filename})

  add_executable(${filename} ${file})
  target_link_libraries(${filename} PRIVATE atchops atlogger)
  add_test(NAME ${filename} COMMAND $<TARGET_FILE:${filename}>)
endforeach()
