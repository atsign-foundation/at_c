#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
"$SCRIPT_DIRECTORY/../../../tools/install.sh"
cd "$SCRIPT_DIRECTORY"
rm -rf bin
cmake -S . -B build
cmake --build build --target install
./bin/reconnection
