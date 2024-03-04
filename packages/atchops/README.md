# atchops

`atchops` is the cryptographic and hashing operations catered for the atProtocol, uses [MbedTLS crypto](https://github.com/Mbed-TLS/mbedtls) as a dependency.

## Building Source

### Installing on Linux/MacOS

Check out the [install.sh](./tools//install.sh) as an example.

To build atchops standalone:

1. Get ahold of the source code either via git clone or from downloading the source from our releases:

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atchops
```

2. CMake configure

```sh
cmake -S . -B build
```

Alternatively, if you have installed MbedTLS and from source already, you can avoid fetching it everytime with `ATCHOPS_FETCH_MBEDTLS=OFF`. Doing this drastically reduces the time it takes to configure the project:

```sh
cmake -S . -B build -DATCHOPS_FETCH_MBEDTLS=OFF
```

If you would not like the static libraries and include header files to be installed on your system directly, you can specify a custom install directory with `-DCMAKE_INSTALL_PREFIX=/path/to/install`:

Example:

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./install
```

The command above will install the static libraries and include header files in the `install` directory in the root of the project. Installing without the `-DCMAKE_INSTALL_PREFIX=./install` flag in the configure step will install the static libraries, include headers, and any binaries in your system directories, such as `/usr/local/lib` and `/usr/local/include`.

Example of the install directory structure:

```bash
.
└── install/
    ├── bin
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

3. Install.


```sh
cmake --build build --target install
```

This is the same as doing `cd build && make install` if you are using something like Unix Makefiles as your generator.

You may need to use `sudo` depending on your system.

## Running Tests

### Running Tests on Linux/MacOS

Check out the [run_ctest.sh](./tools/run_ctest.sh) as an example.

1. Run the CMake configure step with `-DATCHOPS_BUILD_TESTS=ON` flag set to ON

```sh
cmake -S . -B build -DATCHOPS_BUILD_TESTS=ON
```

2. Run `make all` (install step)
```sh
cmake --build build --target all
```

3. Run `ctest`

```sh
cd build/tests
ctest --output-on-failure
```

## Contributing

When creating source files, header files, or tests to certain packages, please follow the documentation in their according README files.

### Creating Tests

If you want to add a test in atclient, simply add a `test_*.c` file in the `tests` directory. CMake will automatically detect it and add it to the test suite. Ensure that the test file is named `test_*.c` or else it will not be detected.

Ensure the file has a `int main(int argc, char **argv)` function and returns 0 on success and not 0 on failure.

### Adding New Source Files

This one is a little more tricky. Adding a new source file to the project requires a few steps:

Add the source file to the `CMakeLists.txt` file in the `src` directory. This is so that CMake knows to compile the file.

Example:

```cmake
target_sources(atchops PRIVATE
    ...
    ${CMAKE_CURRENT_LIST_DIR}/src/folder/new_file.c
    ...
)
```

### Adding New Include Headers

Simply add the header inside of the `include/` directory. CMake will automatically detect it and add it to the include path.

If it is added in a subdirectory (like `include/atchops/`), then the include path will be `atchops/` (e.g. `#include <atchops/new_header.h>`). If it is added in the root of the `include/` directory, then the include path will be the root of the `include/` directory (e.g. `#include <new_header.h>`).