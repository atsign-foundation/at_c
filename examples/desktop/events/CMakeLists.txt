cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

option (TARGET_SRC "Specify the target" REQUIRED)

find_package(atclient REQUIRED CONFIG)
message(STATUS "Found atclient!")

find_package(atchops QUIET)
find_package(MbedTLS QUIET)
find_package(cjson QUIET)



set(examples
  notify
  monitor
)

foreach(example ${examples})
  add_executable(${example} ${CMAKE_CURRENT_LIST_DIR}/${example}.c)
  target_link_libraries(${example} PRIVATE atclient::atclient)
endforeach()

