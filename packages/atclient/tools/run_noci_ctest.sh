#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON -DRUN_NOCI_TESTS=ON 
cmake --build build --target all
cd build/tests
set +e
ctest --verbose
set -e
cd ../..
cmake -S . -B build -D RUN_NOCI_TESTS:BOOL=OFF >/dev/null 2>&1

