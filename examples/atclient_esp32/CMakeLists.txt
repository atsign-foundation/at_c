cmake_minimum_required(VERSION 3.19)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_SOURCE_DIR}/../../packages/atclient
    ${CMAKE_SOURCE_DIR}/../../packages/atchops
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_esp32)