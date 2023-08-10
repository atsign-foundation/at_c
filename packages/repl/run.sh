#!/bin/bash
set -eu
rm -f build/CMakeCache.txt
cmake -S . -B build
sudo cmake --build build --target install
./bin/repl
