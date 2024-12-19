cmake_minimum_required(VERSION 3.19)

project(cram_authenticate LANGUAGES C VERSION 0.0.1)

include(GNUInstallDirs)
include(FetchContent)

find_package(atsdk REQUIRED CONFIG)
message(STATUS "atsdk was found")

add_executable(cram_auth ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(cram_auth PRIVATE atsdk::atclient atsdk::atchops atsdk::atcommons)

# the target executable will be delivered to the packages/cram_authenticate/bin directory, when building the `install` target.
install(TARGETS cram_auth DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin)