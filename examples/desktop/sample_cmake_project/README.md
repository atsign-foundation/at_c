# sample_cmake_project

This is an example desktop CMake project consuming the atclient library.

First step is to build the static libraries and headers. See [atclient](../../packages/atclient/README.md) for instructions on building the source.

Next, add the following to your CMakeLists.txt:

```cmake
find_package(atclient REQUIRED CONFIG)
```

find_package looks for atclient-config.cmake which should be in your `/usr/local/lib/atclient-config.cmake` (if you're on Mac) or similar location. This file helps CMake find the atclient library and headers.

Then you can link against the atclient library:

```cmake
target_link_libraries(my_lib PRIVATE atclient::atclient)
```

Here is a full CMakeLists.txt example:

```cmake
cmake_minimum_required(VERSION 3.19)

project(sample_cmake_project)

find_package(atclient REQUIRED CONFIG)

message(STATUS "Found atclient!")

add_executable(exec ${CMAKE_CURRENT_LIST_DIR}/main.c)

target_link_libraries(exec PRIVATE atclient::atclient)
```
