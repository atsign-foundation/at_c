#!/bin/bash
set -eu

# clean
rm -f build/CMakeCache.txt
sudo rm -f bin/repl

# install dependencies
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"

# 1. Install atsdk
"$SCRIPT_DIRECTORY/../../../tools/install.sh"

# 2. Build REPL
cd "$SCRIPT_DIRECTORY"

## 2a. CMake configure
cmake -S . -B build

## 2b. CMake build
sudo cmake --build build --target install

# 3. Run REPL
./bin/repl $@
