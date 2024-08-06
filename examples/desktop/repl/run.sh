#!/bin/bash
set -eu

FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"

# clean
rm -f build/CMakeCache.txt
rm -f bin/repl

# 1. Install atsdk
"$SCRIPT_DIRECTORY/../../../tools/install.sh"

# 2. Build REPL

## 2a. CMake configure
cmake -S . -B build

## 2b. CMake build
cmake --build build --target install

# 3. Run REPL
./bin/repl $@
