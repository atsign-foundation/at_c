#!/bin/bash
set -eu

# clean
rm -f build/CMakeCache.txt
sudo rm -f bin/repl

# configure
cmake -S . -B build

# build & install
sudo cmake --build build --target install

# run
./bin/repl
