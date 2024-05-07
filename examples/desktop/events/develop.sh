#!/bin/bash

# Usage "./develop.sh notify|monitor"

set -eu

FILE=$1
shift

FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
"$SCRIPT_DIRECTORY/../../../tools/install.sh"
cd $SCRIPT_DIRECTORY

cmake -S . -B build
cmake --build build
./build/"$FILE" $@
