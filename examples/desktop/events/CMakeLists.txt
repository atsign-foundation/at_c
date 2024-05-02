cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

option(ENABLE_SANITIZER "Enable AddressSanitizer" ON)

if (ENABLE_SANITIZER)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

find_package(atsdk REQUIRED CONFIG)

set(examples notify monitor)

foreach(example ${examples})
  add_executable(${example} ${CMAKE_CURRENT_LIST_DIR}/${example}.c)
  target_link_libraries(${example} PRIVATE atsdk::atclient atsdk::cjson)
endforeach()
