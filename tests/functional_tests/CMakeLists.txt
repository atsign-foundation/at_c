option(FIRST_ATSIGN "First atSign used for all functional tests" OFF)
if(NOT "${FIRST_ATSIGN}" STREQUAL OFF)
  message("[ATSDK FUNCTIONAL TESTS] Functional tests override first atsign: ${FIRST_ATSIGN}")
  add_compile_definitions(FIRST_ATSIGN=${FIRST_ATSIGN})
endif()

option(SECOND_ATSIGN "Second atSign for two-way atSign functional tests" OFF)
if(NOT "${SECOND_ATSIGN}" STREQUAL OFF)
  message("[ATSDK FUNCTIONAL TESTS] Functional tests override second atsign: ${SECOND_ATSIGN}")
  add_compile_definitions(SECOND_ATSIGN=${SECOND_ATSIGN})
endif()

option(ATDIRECTORY_HOST "Host for atDirectory functional tests" OFF)
if(NOT "${ATDIRECTORY_HOST}" STREQUAL OFF)
  message("[ATSDK FUNCTIONAL TESTS] Functional tests override atDirectory host: ${ATDIRECTORY_HOST}")
  add_compile_definitions(ATDIRECTORY_HOST=${ATDIRECTORY_HOST})
endif()

option(ATDIRECTORY_PORT "Port for atDirectory functional tests" OFF)
if(NOT "${ATDIRECTORY_PORT}" STREQUAL OFF)
  message("[ATSDK FUNCTIONAL TESTS] Functional tests override atDirectory port: ${ATDIRECTORY_PORT}")
  add_compile_definitions(ATDIRECTORY_PORT=${ATDIRECTORY_PORT})
endif()

cmake_minimum_required(VERSION 3.19)
set(CMAKE_C_STANDARD 99)

project(
  functional_tests
  VERSION 0.0.1
  DESCRIPTION "Functional tests for atsdk"
  HOMEPAGE_URL https://atsign.com
  LANGUAGES C
)

if(NOT DEFINED FUNCTIONAL_TESTS_AS_SUBPROJECT)
  set(FUNCTIONAL_TESTS_AS_SUBPROJECT ON)
  if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(FUNCTIONAL_TESTS_AS_SUBPROJECT OFF)
  endif()
endif()

if(NOT FUNCTIONAL_TESTS_AS_SUBPROJECT)
  find_package(atsdk CONFIG REQUIRED)
else()
  add_library(atsdk::atclient ALIAS atclient)
endif()

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib)

enable_testing()

file(GLOB_RECURSE files ${CMAKE_CURRENT_LIST_DIR}/tests/*test_*.c)

foreach(file ${files})
  # ${filename} - without `.c`
  get_filename_component(filename ${file} NAME)
  string(REPLACE ".c" "" filename ${filename})

  add_executable(${filename} ${file})
  target_include_directories(
    ${filename}
    PRIVATE ${CMAKE_CURRENT_LIST_DIR}/tests/
  )
  target_link_libraries(
    ${filename}
    PRIVATE atsdk::atclient atsdk::functional_tests_lib
  )
  add_test(NAME ${filename} COMMAND ${filename})
endforeach()
