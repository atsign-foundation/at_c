#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DATSDK_BUILD_TESTS=OFF
sudo cmake --build build --target install
