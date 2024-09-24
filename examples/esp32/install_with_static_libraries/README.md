# install_with_static_libraries

## Who Is This For

This example is good for those who have access to the static libraries that were generated on your computer.

This is not the recommended way of doing things, but is possible in case you need to do it this way.

If you want to use our components quickly and easily, we have an example named [install_with_remote_components](../install_with_remote_components/README.md).

## How To Install With Static Libraries

Let's say you have access to the following:

- Static libraries
  - `libatclient.a`
  - `libatchops.a`
  - `libatlogger.a`

- Include Header Files
  - `include/atchops/`
  - `include/atclient/`
  - `include/atlogger/`
  - `include/cjson/`
  - `include/everest/`
  - `include/mbedtls/`
  - `include/psa/`
  - `include/uuid4/`

  (All the dependencies such as cjson, mbedtls, and uuid4 are already included in the static libraries)

1. Ensure your project structure looks like this:

```plaintext
.
├── CMakeLists.txt
├── include
│   ├── atchops
│   │   ├── atchops.h
│   │   └── ...
│   ├── atclient
│   │   ├── atclient.h
│   │   └── ...
│   └── atlogger
│       ├── atlogger.h
│       └── ...
├── lib
│   ├── libatchops.a
│   ├── libatclient.a
│   └── libatlogger.a
└── main
    └── main.c
```

If your project doesn't look like this, then you need to move your files around.

2. Your `main/CMakeLists.txt` should look like this:

```cmake
idf_component_register(
    SRCS "main.c"
    REQUIRES spi_flash nvs_flash app_update
    INCLUDE_DIRS "../include"
)

set(LIBRARY_PATH ${CMAKE_CURRENT_LIST_DIR}/../lib)

add_library(atclient STATIC IMPORTED)
set_target_properties(atclient PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libatclient.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE atclient)

add_library(atchops STATIC IMPORTED)
set_target_properties(atchops PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libatchops.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE atchops)

add_library(atlogger STATIC IMPORTED)
set_target_properties(atlogger PROPERTIES IMPORTED_LOCATION ${LIBRARY_PATH}/libatlogger.a)
target_link_libraries(${COMPONENT_LIB} PRIVATE atlogger)
```

3. Your `./CMakeLists.txt` is your typical root CMakeLists.txt file:

```cmake
cmake_minimum_required(VERSION 3.24)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_esp32_static_libraries)
```

4. Build your project:

```bash
idf.py build
```
