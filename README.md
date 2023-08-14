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

### Building on Linux/MacOS

1. Clone the repository and change directory into `packages/atclient`.

```sh
git clone https://github.com/atsign-foundation/at_c.git
cd at_c/packages/atclient
```

2. CMake configure

```sh
cmake -S . -B build
```

3. Install

```sh
cmake --build build --target install
```

### Building on Windows

Coming Soon!

## Usage

To use `atclient`, you can use `find_package` in your CMakeLists.txt file.

```cmake
cmake_minimum_required(VERSION 3.10)

project(myproject)

find_package(atclient REQUIRED CONFIG)

add_executable(myproject src/main.cpp)

target_link_libraries(myproject PRIVATE atclient::atclient)
```

## Maintainers

- [XavierChanth](https://github.com/XavierChanth)
- [JeremyTubongbanua](https://github.com/JeremyTubongbanua)