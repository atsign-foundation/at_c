#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY/.."

# 1. Install atSDK
../../tools/install.sh

# 2. Run tests
cmake -S . -B build
cmake --build build
ctest --test-dir build -VV
