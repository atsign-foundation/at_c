#!/bin/bash
set -eu

# clean
rm -f build/CMakeCache.txt
sudo rm -f bin/repl

# install dependencies
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
"$SCRIPT_DIRECTORY/../../packages/atclient/tools/install.sh"
cd "$SCRIPT_DIRECTORY"

# configure
cmake -S . -B build

# build & install
sudo cmake --build build --target install

# run
./bin/repl $@
