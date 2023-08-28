# atclient_esp32_source

This example shows you how to use atclient/atchops in your own ESP-IDF project by providing the path to the source code.

## How to Consume Via Source Code

In `make/CMakeLists.txt`, be sure to add the atclient and atchops components to the REQUIRES list:

```cmake
idf_component_register(
    SRCS "main.c"
    REQUIRES mbedtls atclient atchops
)
```

In `./CMakeLists.txt`, add the path to the atclient and atchops source code via the EXTRA_COMPONENT_DIRS variable:

```cmake
set(EXTRA_COMPONENT_DIRS
    ${CMAKE_SOURCE_DIR}/../../packages/atclient # match this to be the path to the root CMakeLists.txt of atclient package
    ${CMAKE_SOURCE_DIR}/../../packages/atchops # match this to be the path to the root CMakeLists.txt of atchops package
)
```

## Running the Example

To run the example, you will need the ESP-IDF toolchain installed. See [ESP-IDF's Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) for more information. Ensure that your ESP32 is plugged into your computer with a micro USB data cable.

Running the example via `get_idf && idf.py build && idf.py flash monitor` will give you something similar to:

```sh
atchops_base64_encode: 0
src: Lemonade!
dst: TGVtb25hZGUh
dst bytes: 
54 47 56 74 62 32 35 68 5a 47 55 68
```