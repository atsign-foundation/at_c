cmake_minimum_required(VERSION 3.19)

project(send_enroll_request LANGUAGES C VERSION 0.0.1)

include(GNUInstallDirs)
include(FetchContent)

find_package(atsdk CONFIG REQUIRED)
message(STATUS "[atsdk] Found package!")

add_executable(send_enroll_request ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(send_enroll_request PRIVATE atsdk::atclient atsdk::atchops atsdk::atcommons atsdk::atauth)

# the target executable will be delivered to the packages/send_enroll_request/bin directory, when building the `install` target.
install(TARGETS send_enroll_request DESTINATION ${CMAKE_CURRENT_LIST_DIR}/bin)