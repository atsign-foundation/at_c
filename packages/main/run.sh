#!/bin/bash
set -eu
rm -f build/CMakeCache.txt
rm -f install/bin/main
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./install
cmake --build build --target install
# clear
./install/bin/main