cmake_minimum_required(VERSION 3.19.2)

project(repl)

set(CMAKE_C_STANDARD 99)

add_executable(repl ${CMAKE_SOURCE_DIR}/src/main.c)

message(STATUS "CMAKE_SOURCE_DIR: ${CMAKE_SOURCE_DIR}")

find_library(AT_CLIENT_LIB libat_client.a ${CMAKE_SOURCE_DIR}/lib)
find_library(AT_CHOPS libat_chops.a ${CMAKE_SOURCE_DIR}/lib)

target_link_libraries(repl PRIVATE ${AT_CLIENT_LIB})
target_link_libraries(repl PRIVATE ${AT_CHOPS})
target_include_directories(repl PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(repl PRIVATE ${CMAKE_SOURCE_DIR}/include/at_client)
target_include_directories(repl PRIVATE ${CMAKE_SOURCE_DIR}/include/at_chops)

# target_include_directories(repl PRIVATE ${CMAKE_SOURCE_DIR}/include)
# target_include_directories(repl PRIVATE ${CMAKE_SOURCE_DIR}/include/at_client)
# target_include_directories(repl PRIVATE ${CMAKE_SOURCE_DIR}/include/at_chops)
# target_link_libraries(repl PRIVATE ${CMAKE_SOURCE_DIR}/lib/libat_client.a)
# target_link_libraries(repl PRIVATE ${CMAKE_SOURCE_DIR}/lib/libat_chops.a)
# target_link_libraries(repl PRIVATE ${CMAKE_SOURCE_DIR}/lib/libmbedcrypto.a)
# target_link_libraries(repl PRIVATE ${CMAKE_SOURCE_DIR}/lib/libmbedtls.a)
# target_link_libraries(repl PRIVATE ${CMAKE_SOURCE_DIR}/lib/libmbedx509.a)
