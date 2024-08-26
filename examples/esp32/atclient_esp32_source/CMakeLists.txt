cmake_minimum_required(VERSION 3.19)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atchops
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atclient
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atlogger
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_esp32_source)