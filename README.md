<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_c)

# at_c

`at_c` is the client C implementation of the atProtocol

## Packages

- `atchops` stands for cryptographic and hashing operations catered for the atProtocol, uses [MbedTLS crypto](https://github.com/Mbed-TLS/mbedtls) as a dependency.
- `atclient` is the core dependency for anything Atsign technology related. atclient depends on [atchops](./packages/atchops/README.md) and [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
- `repl` is a demo application using atclient

## Building Source

To build the source code you will need to have [CMake](https://cmake.org/) installed.

Most of the following steps will work with `atchops` and `atclient`:

- [Installing on Linux/MacOS](#installing-on-linuxmacos)
- [Running Tests on Linux/MacOS](#running-tests-on-linuxmacos)
- [Installing on Windows](#installing-on-windows)

### Installing on Linux/MacOS

1. Get ahold of the source code either via git clone or from downloading the source from our releases:

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atclient
```

2. CMake configure

```sh
cmake -S . -B build
```

If you have installed MbedTLS and/or AtChops from source already, you can avoid fetching it everytime with `ATCLIENT_FETCH_MBEDTLS=OFF` and `ATCLIENT_FETCH_ATCHOPS=OFF` respectively:

```sh
cmake -S . -B build -DATCLIENT_FETCH_MBEDTLS=OFF -DATCLIENT_FETCH_ATCHOPS=OFF
```

3. Install

```sh
cmake --build build --target install
```

4. Building the source code will allow you to use the `atclient` library in your own CMake projects:

```cmake
find_package(atclient REQUIRED CONFIG)
target_link_libraries(myproj PRIVATE atclient::atclient)
```

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

3. Build (target is all by default)

```sh
cmake --build build
```

4. Run tests

```sh
cd build/tests && ctest -V --output-on-failure --timeout 10
```

`--timeout 10` times out tests after 10 seconds

### Installing on Windows

Coming Soon!

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to properly fork and open a pull request.

When creating 

- [Creating Tests](#creating-tests)
- [Adding New Source Files](#adding-new-source-files)
- [Adding New Include Headers](#adding-new-include-headers)

### Creating Tests

If you want to add a test in atclient, simply add a `test_*.c` file in the `tests` directory. CMake will automatically detect it and add it to the test suite. Ensure that the test file is named `test_*.c` or else it will not be detected.

Ensure the file has a `int main(int argc, char **argv)` function and returns 0 on success and not 0 on failure.

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

If it is added in a subdirectory (like `include/atclient/`), then the include path will be `atclient/` (e.g. `#include <atclient/new_header.h>`)

## Maintainers

- [XavierChanth](https://github.com/XavierChanth)
- [JeremyTubongbanua](https://github.com/JeremyTubongbanua)