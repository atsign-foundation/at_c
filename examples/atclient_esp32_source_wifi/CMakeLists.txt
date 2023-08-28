cmake_minimum_required(VERSION 3.19)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../packages/atclient # match this to be the path to the root CMakeLists.txt of atclient package
    ${CMAKE_CURRENT_LIST_DIR}/../../packages/atchops # match this to be the path to the root CMakeLists.txt of atchops package
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_esp32_source)