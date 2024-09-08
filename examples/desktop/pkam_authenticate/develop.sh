#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
"$SCRIPT_DIRECTORY/../../../tools/install.sh"
cd "$SCRIPT_DIRECTORY"
cmake -S . -B build
cmake --build build --target all
echo "Running main:"
echo ""
echo ""
cd build && ./main
cd ..
