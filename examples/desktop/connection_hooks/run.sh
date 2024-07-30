#!/bin/bash
set -eu

# Clean
rm -f build/CMakeCache.txt
rm -f bin/main

# Install dependencies
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"

# Install atsdk
"$SCRIPT_DIRECTORY/../../../tools/install.sh"

# Build
cd "$SCRIPT_DIRECTORY"

## CMake configure
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

## CMake build
cmake --build build --target install

# Run
./bin/main $@
