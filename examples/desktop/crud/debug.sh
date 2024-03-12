#!/bin/bash

# This script is used for manual testing
# Execute this script via ./debug.sh <file> (example: ./debug.sh get_publickey.c)

set -e
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"

FILE=$1

"$SCRIPT_DIRECTORY/../../../packages/atclient/tools/install.sh"
cd "$SCRIPT_DIRECTORY"

rm -f build/exec
cmake -S . -B build -DTARGET_SRC="$FILE"
cmake --build build
./build/exec
