#!/bin/bash
set -eu

FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..
cmake -S . -B build -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF
cmake --build build
