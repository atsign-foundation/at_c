cmake_minimum_required(VERSION 3.19)

project(at_talk
    LANGUAGES C
    VERSION 0.1.0
)

add_executable(main
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
)

find_package(MbedTLS CONFIG REQUIRED)
find_package(atchops CONFIG REQUIRED)
find_package(atclient CONFIG REQUIRED)

target_link_libraries(
    main
    PRIVATE atclient::atclient
    MbedTLS::mbedtls atchops::atchops
)