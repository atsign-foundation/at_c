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
