#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..
rm -rf build/tests
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON
cmake --build build --target all
cd build/tests
ctest -V
