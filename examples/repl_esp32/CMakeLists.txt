cmake_minimum_required(VERSION 3.19)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../packages/atchops
    ${CMAKE_CURRENT_LIST_DIR}/../../packages/atclient
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(repl_esp32)