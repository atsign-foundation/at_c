# at_c

Project structure:

`archetypes`: contains useful templates for compiling applications for this library.
`build`: cmake builds to this folder.
`include`: declarations (header files).
`src`: definitions (source code).
`lib`: staticly linked libraries.
`targets`: additional configuration for build targets.
`test`: contains the tests.

Usage:

Build to the current platform: `make`

Setup esp32 build tools: `make esp32-tools`

Setup esp32 build environment: `make esp32-env`

Build to esp32: `make esp32`