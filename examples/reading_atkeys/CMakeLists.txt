cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

find_package(atclient REQUIRED CONFIG)
message(STATUS "Found atclient!")
find_package(MbedTLS REQUIRED CONFIG)
message(STATUS "Found MbedTLS!")
find_package(atchops REQUIRED CONFIG)
message(STATUS "Found atchops!")

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/main.c)

target_link_libraries(main PRIVATE

    # atchops::atchops MbedTLS::mbedtls
    atclient::atclient)
