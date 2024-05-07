#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..

"../../tools/install.sh"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target $1

./build/$1
