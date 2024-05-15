#!/bin/bash
set -eu

# clean
rm -f build/CMakeCache.txt
rm -f bin/at_talk

# install dependencies
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
"$SCRIPT_DIRECTORY/../../../tools/install.sh"
cd "$SCRIPT_DIRECTORY"

# configure
cmake -S . -B build

# build & install
cmake --build build --target install

# run
./bin/at_talk $@