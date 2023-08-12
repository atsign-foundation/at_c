#!/bin/bash
set -eu
cd ../atclient
./install-system.sh
cd ../repl
rm -f build/CMakeCache.txt
cmake -S . -B build
sudo rm -f bin/repl
sudo cmake --build build --target install
./bin/repl
