cmake_minimum_required(VERSION 3.19)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../atchops
    ${CMAKE_CURRENT_LIST_DIR}/../atclient
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_espidf)