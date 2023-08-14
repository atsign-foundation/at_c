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

Building the source code will allow you to use the `atclient` library in your own CMake projects:

```cmake
find_package(atclient REQUIRED CONFIG)
target_link_libraries(myproj PRIVATE atclient::atclient)
```

The first step to achieve this is to first get ahold of the source code either via git clone or from downloading the source from our releases:

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atclient
```

Once you have completed this step, you can branch off to any of the following:

- [Installing on Linux/MacOS](#installing-on-linuxmacos)
- [Running Tests on Linux/MacOS](#running-tests-on-linuxmacos)
- [Installing on Windows](#installing-on-windows)

### Installing on Linux/MacOS

1. CMake configure

```sh
cmake -S . -B build
```

If you have installed MbedTLS and/or AtChops from source already, you can avoid fetching it everytime:

```sh
cmake -S . -B build -DATCLIENT_FETCH_MBEDTLS=OFF -DATCLIENT_FETCH_ATCHOPS=OFF
```

3. Install

```sh
cmake --build build --target install
```

### Running Tests on Linux/MacOS

1. CMake configure with `-DATCLIENT_BUILD_TESTS=ON`

```sh
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON
```

2. Build (target is all by default)

```sh
cmake --build build
```

3. Run tests

```sh
cd build/tests && ctest -V --output-on-failure --timeout 10
```

`--timeout 10` times out tests after 10 seconds

### Installing on Windows

Coming Soon!

## Maintainers

- [XavierChanth](https://github.com/XavierChanth)
- [JeremyTubongbanua](https://github.com/JeremyTubongbanua)