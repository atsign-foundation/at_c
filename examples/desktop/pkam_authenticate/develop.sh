#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY/../../packages/atclient"
cmake -S . -B build
sudo cmake --build build --target install
cd "$SCRIPT_DIRECTORY/../../examples/pkam_authenticate"
cmake -S . -B build
cmake --build build --target all
echo "Running main:"
echo ""
echo ""
cd build && ./main
cd ..
