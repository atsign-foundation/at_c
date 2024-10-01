cmake_minimum_required(VERSION 3.19)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atlogger
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atchops
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atclient
    ${CMAKE_CURRENT_LIST_DIR}/../../../../uuid4
)

project(install_with_local_components)