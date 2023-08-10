#!/bin/bash
set -eu
sudo rm -rf build
rm -f build/CMakeCache.txt
cmake -S . -B build
sudo cmake --build build --target install/local
./install/repl