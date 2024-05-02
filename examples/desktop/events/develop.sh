#!/bin/bash
set -eu

FILE=$1
shift

FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"

sudo bash "$SCRIPT_DIRECTORY/../../../tools/clean_install.sh"

cd $SCRIPT_DIRECTORY
cmake -S . -B build -DTARGET_SRC="$FILE.c"
cmake --build build
echo "Running main:"
echo ""
echo ""
cd build
./$FILE "$@"
cd ..
