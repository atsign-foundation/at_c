# at_c

## Project structure

`archetypes`: contains useful templates for compiling applications for this library.  
`build`: cmake builds to this folder.  
`include`: declarations (header files).  
`src`: definitions (source code).  
`lib`: staticly linked libraries.  
`targets`: additional configuration for build targets.  
`test`: contains the tests.

## Tools

The entire build pipeline can be run via python using `./tool.py`.
The tool expects a platform `-p`, framework `-f`, and command.

Example:
Build for esp32 using espidf framework: `./tool.py -p esp32 -f espidf build`

## Development Getting Started

The following steps demonstrates how to `initialize`, `build`, and `test` a hello world program for the `desktop` platform and `mbedtls` framework

Prerequisites
- [Git](https://git-scm.com/downloads)
- [Python 3.9+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [CMake 3.25.2](https://cmake.org/download/)

Run the following in your terminal:

1. This commmand ensures CMake 3.25.2 is installed, otherwise it installs it for you. `-p desktop` means use the `desktop` platform, `-f mbedtls` means use the `mbedtls` framework, and the used command is `init`.

```sh
python tool.py -p desktop -f mbedtls init
```

2. Running this command updates the git submodules (inside `deps/`). See `.gitmodules` for more information about the used git submodules.

```sh
git submodule update --init --recursive
```

3. Write `hello.c` in `test/`

```c
#include <stdio.h>
#include "at_chops.h"

int main()
{
    printf("Hello, World!\n");
    return 0;
}
```

4. Run the `build` command

```sh
python tool.py -p desktop -f mbedtls build
```

5. Add a test executable inside of the root `CMakeLists.txt`. The following must be changed accordingly: `test_hello`, `test/hello.c`, and `HELLO`; where some need to be changed multiple times.

```
add_executable(test_hello test/hello.c)
target_link_libraries(test_hello PRIVATE at_client)
add_test(
  NAME HELLO
  COMMAND $<TARGET_FILE:test_hello>
)
```

6. Run the `test` command

```sh
python tool.py -p desktop -f mbedtls test
```

7. You should receive a similar output:

```sh
Running tests...
test_base64 exited with code -11
atest_aes_ctr exited with code -10
Hello, World!
test_hello passed!

2 tests failed!
```
