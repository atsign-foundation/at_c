# playground

This is a template for desktop examples.

Simply copy this folder and start building your own desktop example.

This example is particularly useful for developing the atSDK at the same time as testing application code.

## tools

There's an array of tools for building desktop applications. Here are some of them:

- [build.sh](./tools/build.sh) - builds the application (CMake configure and cmake --build build)
- [debug_build.sh](./tools/debug_build.sh) - same as build.sh but in debug mode
- [clean.sh](./tools/clean.sh) - cleans the build directory
- [valgrind.sh](./tools/valgrind.sh) - runs the application with valgrind (example usage: `./tools/valgrind.sh ./build/main <args>`), you are required to run `./tools/debug_build.sh` before running this script