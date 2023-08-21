# atclient_esp32_static

This is an example of how to use the built static libraries from [atclient_espidf](../../packages/atclient_espidf/README.md).

## Consuming AtClient/AtChops as Static Libraries

You will need to have built the static libraries from [atclient_espidf](../../packages/atclient_espidf/README.md) before you can consume them in your own project.

Once you have that, be sure to create the following directories in your project:

- `components/atclient`
- `components/atchops`

And in each directory, create a CMakeLists.txt.

`components/atclient/CMakeLists.txt`:

```cmake
# register this directory as a component
idf_component_register()

add_prebuilt_library(atclient ${CMAKE_CURRENT_LIST_DIR}/lib/libatclient.a REQUIRES mbedtls atchops)

target_include_directories(atclient INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(${COMPONENT_LIB} INTERFACE atclient) # add it to the component library
```

`components/atchops/CMakeLists.txt`:

```cmake
# register this directory as a component
idf_component_register()

add_prebuilt_library(atchops ${CMAKE_CURRENT_LIST_DIR}/lib/libatchops.a REQUIRES mbedtls)

target_include_directories(atchops INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(${COMPONENT_LIB} INTERFACE atchops) # add it to the component library
```

Then in your `main/CMakeLists.txt`, be sure to REQUIRE the atclient and atchops components:

```cmake
idf_component_register(
    SRCS "main.c"
    REQUIRES atclient atchops
)
```

Your root project `./CMakeLists.txt` can remain the same as any regular ESP-IDF root CMakeLists.txt.

```cmake
cmake_minimum_required(VERSION 3.19)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(atclient_esp32)
```

## Running this example

This example requires the ESP-IDF toolchain to be installed. See [ESP-IDF's Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) for more information.

Ensure that your ESP32 is plugged into your computer with a micro USB data cable.

1. Get IDF

```sh
get_idf
```

2. Build

```sh
idf.py build
```

3. Flash and Monitor to your ESP32

```sh
idf.py flash monitor
```

4. Your output will be similar to the following:

```sh
atchops_base64_encode: 0
src: Lemonade!
dst: TGVtb25hZGUh
dst bytes: 
54 47 56 74 62 32 35 68 5a 47 55 68 
```