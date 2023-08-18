cmake_minimum_required(VERSION 3.19)

set(EXTRA_COMPONENT_DIRS ${CMAKE_SOURCE_DIR}/../atclient ${CMAKE_SOURCE_DIR}/../atchops)
set(COMPONENTS atclient atchops main)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_esp32)