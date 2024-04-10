#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..
cmake -S . -B build -DATCHOPS_BUILD_TESTS=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
sudo cmake --build build --target install
