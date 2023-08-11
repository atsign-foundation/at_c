cmake_minimum_required(VERSION 3.19)

project(main)

include(GNUInstallDirs)

find_package(MbedTLS REQUIRED)
find_package(atchops REQUIRED)

add_executable(main 
    ${CMAKE_CURRENT_LIST_DIR}/main.c
)

target_link_libraries(
    main
    PRIVATE MbedTLS::mbedcrypto MbedTLS::mbedx509 MbedTLS::mbedtls
    PRIVATE atchops::atchops
)

target_include_directories(
    main
    PRIVATE "/usr/local/include"
)

install(
    TARGETS main
    RUNTIME DESTINATION bin
)