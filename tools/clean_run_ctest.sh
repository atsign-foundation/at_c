#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..
rm -rf build
cmake -S . -B build -DATSDK_BUILD_TESTS=ON
cmake --build build --target all
cd build/tests
ctest --output-on-failure --timeout 2
