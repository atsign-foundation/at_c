# atclient_espidf

Use this package to build atclient static libraries & include headers for your ESP-IDF projects.

<!-- build table of contents with: https://derlin.github.io/bitdowntoc/ -->

- [atclient_espidf](#atclient_espidf)
  - [Requirements](#requirements)
  - [Consuming AtClient in your ESP-IDF Project](#consuming-atclient-in-your-esp-idf-project)
    - [Source Code](#source-code)
    - [Static Libraries](#static-libraries)
      - [1. Build Static Libraries through Source Code](#1-build-static-libraries-through-source-code)
      - [2. Use Static Libraries as a Prebuilt Library](#2-use-static-libraries-as-a-prebuilt-library)

## Requirements

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) - you will need the `idf.py` tool when building the static libraries
- [Git](https://git-scm.com/) - to clone this repository

## Consuming AtClient in your ESP-IDF Project

There are two ways to consume atclient in your ESP-IDF project.

1. [Source Code](#source-code) - the first way is when you have access to the source code (as a submodule or downloaded source code).

2. [Static Libraries](#static-libraries) - the second is when you have access to the static libraries and include headers.

### Source Code

It is assumed you have access to the source code of this repository whether it is downloaded through our releases or cloned from git (via: `git clone https://github.com/atsign-foundation/at_c.git`)

1. In your ESP-IDF project, your file structure should look something like this:

```bash
├── main/
│   └── CMakeLists.txt
└── CMakeLists.txt
```

2. Add atclient and atchops as extra component directories to the root `./CMakeLists.txt`.

```
set(EXTRA_COMPONENT_DIRS
    /path/to/atclient
    /path/to/atchops
)
```

Your `./CMakeLists.txt` will look similar to this:

```cmake
cmake_minimum_required(VERSION 3.19)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(myproj)
```

3. Add the `atclient` and `atchops` components as dependencies to your main components's CMakeLists.txt.

```
REQUIRES atclient atchops
```

Where `main/CMakeLists.txt` may look similar to:

```cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES atclient atchops mbedtls nvs_flash esp_wifi
)
```

### Static Libraries

#### 1. Build Static Libraries through Source Code

Building the static libraries will only build atclient and atchops. This will not build MbedTLS which is an underlying dependency for atclient and atchops.

1. Clone this repository

```sh
git clone https://github.com/atsign-foundation/at_c
```

2. Go into this directory

```sh
cd at_c/packages/atclient_espidf
```

3. get_idf

```sh
get_idf
```

4. Build

```sh
idf.py build
```

5. This will build two directories: `include/` and `lib/` in the root of the project.

```bash
├── include/
│   ├── atclient/
│   │   └── *.h
│   └── atchops/
│       └── *.h
└── lib/
    ├── libatclient.a
    └── libatchops.a
```

#### 2. Use Static Libraries as a Prebuilt Library

You can create ESP-IDF components out of static libraries (which is how we are showing you how to do it), or you can add it to your main component's CMakeLists.txt, which is how [ESP-IDF's example](https://github.com/espressif/esp-idf/tree/master/examples/build_system/cmake/import_prebuilt) shows you how to do it.

The following steps will show you how to create separate ESP-IDF components (atclient and atchops) and have them each require on MbedTLS.

1. Create `components/atclient` and `components/atchops` directories in your ESP-IDF project. Create a blank CMakeLists.txt in each directory

Your project structure may look similar to:

```bash
├── components/
│   ├── atclient/
│   │   └── CMakeLists.txt
│   └── atchops/
│       └── CMakeLists.txt
├── main/
│   └── CMakeLists.txt
└── CMakeLists.txt
```

2. Add the built static libraries and include headers to their respective component directories.

Your project structure may look similar to:

```bash
├── components/
│   ├── atclient/
│   │   ├── CMakeLists.txt
│   │   ├── include/atclient/
│   │   │   └── *.h
│   │   └── lib/
│   │       └── libatclient.a
│   └── atchops/
│       ├── CMakeLists.txt
│       ├── include/atchops/
│       │   └── *.h
│       └── lib/
│           └── libatchops.a
├── main/
│   └── CMakeLists.txt
└── CMakeLists.txt
```

3. In each CMakeLists.txt, register the component and add the static library to the `${COMPONENT_LIB}`:

In `components/atclient/CMakeLists.txt`:

```cmake
idf_component_register()

add_prebuilt_library(atclient ${CMAKE_CURRENT_LIST_DIR}/lib/libatclient.a
    REQUIRES mbedtls
)

target_include_directories(atclient INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(atclient INTERFACE mbedtls)
```

In `components/atchops/CMakeLists.txt`:

```cmake

idf_component_register()

add_prebuilt_library(atchops ${CMAKE_CURRENT_LIST_DIR}/lib/libatchops.a
    REQUIRES mbedtls
)

target_include_directories(atchops INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(atchops INTERFACE mbedtls)
```

4. Depend on `atchops` and `atclient` in your main component:

In `main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES atclient atchops
)
```
