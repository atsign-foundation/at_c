# sample_cmake_project

This is an example desktop CMake project consuming the atclient library.

First step is to build the static libraries and headers. See [atclient](../../../README.md) for instructions on building the source.

Secondly, add the following to your CMakeLists.txt:

```cmake
find_package(atsdk REQUIRED CONFIG)
```

find_package looks for atsdk-config.cmake which should be in your `/usr/local/lib/atsdk-config.cmake` (if you're on Mac) or similar location. This file helps CMake find the atclient library and headers.

This `.cmake` file is generated when you build the atsdk library, which should have been done in the previous step.

Thirdly, you may link against the atsdk library:

```cmake
target_link_libraries(my_lib PRIVATE atsdk::atclient)
```

Here is a full CMakeLists.txt example:

```cmake
cmake_minimum_required(VERSION 3.19)
project(sample_cmake_project)

find_package(atsdk REQUIRED CONFIG)
message(STATUS "[atsdk] Found package!")

add_executable(main ${CMAKE_CURRENT_LIST_DIR}/main.c)
target_link_libraries(main PRIVATE atsdk::atclient)
```

Next, you can build your project:

```bash
cmake -S . -B build
cmake --build build
```

This will build your project with the atclient library.

To run the project:

```bash
./build/main
```
