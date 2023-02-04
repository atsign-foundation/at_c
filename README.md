# at_c

Project structure:

`archetypes`: contains useful templates for compiling applications for this library.
`build`: cmake builds to this folder.
`include`: declarations (header files).
`src`: definitions (source code).
`lib`: staticly linked libraries.
`targets`: additional configuration for build targets.
`test`: contains the tests.

Tools:

Python based build tools, run with: `./<filename> <command> [options]`

`default`: The default build tool, for building on the local platform.
`esp32`: Used for setting up esp32 environment and building with it.