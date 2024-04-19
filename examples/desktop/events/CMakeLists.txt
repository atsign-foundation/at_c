cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

option (TARGET_SRC "Specify the target" REQUIRED)

find_package(atclient REQUIRED CONFIG)
message(STATUS "Found atclient!")

find_package(atchops QUIET)
find_package(MbedTLS QUIET)
find_package(cjson QUIET)



add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/${TARGET_SRC})

target_link_libraries(exec PRIVATE atclient::atclient)
