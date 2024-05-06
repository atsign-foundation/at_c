# atclient

atclient is the core dependency for anything Atsign technology related. atclient depends on [atchops](../atchops/README.md) and [MbedTLS](https://github.com/Mbed-TLS/mbedtls).

This client SDK implements the atProtocol. It is written in C and is intended to be used as a library in other C/C++ applications, such as embedded systems. This package and the following documentation will assist you in building and using the C SDK for desktop. To use this SDK in something like an ESP32, checkout [atclient_espidf](../atclient_espidf/README.md).

It is not mandatory to build [atchops](../atchops/README.md) or [MbedTLS](https://github.com/Mbed-TLS/mbedtls) from source to use this package. However, you have the option of doing so if you want faster building/debugging times. Our [CMakeLists.txt](./CMakeLists.txt) allows the option to build atclient with or without installing [atchops](../atchops/README.md) or [MbedTLS](https://github.com/Mbed-TLS/mbedtls) beforehand.

<!-- build table of contents with: https://derlin.github.io/bitdowntoc/ -->

- [atclient](#atclient)
   * [Building Source](#building-source)
      + [Installing on Linux/MacOS](#installing-on-linuxmacos)
      + [Installing on Windows](#installing-on-windows)
   * [Running Tests](#running-tests)
      + [Running Tests on Linux/MacOS](#running-tests-on-linuxmacos)
   * [Contributing](#contributing)
      + [Creating Tests](#creating-tests)
      + [Adding New Source Files](#adding-new-source-files)
      + [Adding New Include Headers](#adding-new-include-headers)


## Building Source

To build the source code you will need to have [CMake](https://cmake.org/) installed like [Unix Makefiles](https://cmake.org/cmake/help/latest/generator/Unix%20Makefiles.html) (which is installed by default on most Linux distros).

### Installing on Linux/MacOS

1. Get ahold of the source code either via git clone or from downloading the source from our releases:

Git clone sample:

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atclient
```

2. CMake configure

This is the configure step. -S specifies the source directory and -B specifies the build directory. The `.` specifies the current directory.

```sh
cmake -S . -B build
```

Alternatively, if you would not like the static libraries and include header files to be installed on your system directly, you can specify a custom install directory with `-DCMAKE_INSTALL_PREFIX=/path/to/install`.

For example: `cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./install`.

The command above will install the static libraries and include header files in the `install` directory in the root of the project. Installing without the `-DCMAKE_INSTALL_PREFIX=./install` flag in the configure step will install the static libraries, include headers, and any binaries in your system directories, such as `/usr/local/lib` and `/usr/local/include`.

Example of the install directory structure:

```bash
.
└── install/
    ├── bin/
    ├── include/
    │   ├── atclient/
    │   │   └── *.h
    │   ├── atchops/
    │   │   └── *.h
    │   └── mbedtls/
    │       └── *.h
    └── lib/
        ├── cmake/
        │   ├── atclient/
        │   │   └── atclient-config.cmake
        │   └── atchops/
        │       └── atchops-config.cmake
        ├── libatchops.a
        ├── libatclient.a
        ├── libmbedtls.a
        ├── libmbedcrypto.a
        └── libmbedx509.a
```

3. Once the configure step is complete, run install.

```sh
cmake --build build --target install
```

This is the same as doing `cd build && make install` if you are using something like Unix Makefiles as your generator.

You may need to use `sudo` depending on your system.

This step will install the static libraries and include headers in your system directories, such as `/usr/local/lib` and `/usr/local/include`. But if you specified `-DCMAKE_INSTALL_PREFIX=./install`, it will install the static libraries and include headers in the `install` directory in the root of the project.

4. Building the source code will allow you to use the `atclient` library in your own CMake projects:

```cmake
find_package(atclient REQUIRED CONFIG)
target_link_libraries(myproj PRIVATE atclient::atclient)
```

### Installing on Windows

Coming Soon!

For now, here are some experimental commands that *may* work:

```
cmake -S . -B build
cmake --build build --config Debug
```

You may also specify a generator in the configure step with something like: `-G "MinGW Makefiles"`

## Running Tests

### Running Tests on Linux/MacOS

1. Get ahold of the source code either via git clone or from downloading the source from our releases:

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atclient
```

2. CMake configure with `-DATCLIENT_BUILD_TESTS=ON`

```sh
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON
```

3. Build (target is all by default, so the following command will build all targets)

```sh
cmake --build build
```

This is the same as doing `cd build && make all`, if you are using something like Unix Makefiles as your generator.

4. Run tests

```sh
cd build/tests && ctest -V --timeout 10
```

`--timeout 10` times out tests after 10 seconds

`-V` will output any stdout lines from the tests.

You may also do something like `ctest --output-on-failure --test-dir build`, where `--output-on-failure` will output any stdout lines from the tests if they fail and `--test-dir build` specifies the directory where the tests are located (to avoid having to do `cd` beforehand).

## Contributing

When creating source files, header files, or tests to certain packages, please follow the documentation in their according README files.

### Adding New Source Files

This one is a little more tricky. Adding a new source file to the project requires a few steps:

Add the source file to the `CMakeLists.txt` file in the `src` directory. This is so that CMake knows to compile the file.

Example:

```cmake
target_sources(atclient PRIVATE
    ...
    ${CMAKE_CURRENT_LIST_DIR}/src/folder/new_file.c
    ...
)
```

### Adding New Include Headers

Simply add the header inside of the `include/` directory. CMake will automatically detect it and add it to the include path.

If it is added in a subdirectory (like `include/atclient/`), then the include path will be `atclient/` (e.g. `#include <atclient/new_header.h>`). Putting your header file in a subdirectory is recommended to help keep our header files consistent and avoid any naming conflicts.

### Adding New Tests

If you want to add a test in atclient, simply add a `test_*.c` file in the `tests` directory. CMake will automatically detect it and add it to the test suite. Ensure that the test file is named `test_*.c` or else it will not be detected.

Ensure the file has a `int main(int argc, char **argv)` function and returns 0 on success and not 0 on failure.