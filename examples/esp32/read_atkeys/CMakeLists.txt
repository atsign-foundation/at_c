cmake_minimum_required(VERSION 3.24)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atclient
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atchops
    ${CMAKE_CURRENT_LIST_DIR}/../../../packages/atlogger
    ${CMAKE_CURRENT_LIST_DIR}/../../../../uuid4
)

set(PARTITION_TABLE_CUSTOM_FILENAME ${CMAKE_CURRENT_LIST_DIR}/partitions.csv)
set(PARTITION_TABLE_FILENAME ${PARTITION_TABLE_CUSTOM_FILENAME})

project(read_atkeys)
