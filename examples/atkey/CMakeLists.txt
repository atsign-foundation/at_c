cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

find_package(atclient REQUIRED CONFIG)
find_package(MbedTLS REQUIRED CONFIG)
find_package(atchops REQUIRED CONFIG)


add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/main.c)

target_link_libraries(exec PRIVATE atclient::atclient atchops::atchops MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
