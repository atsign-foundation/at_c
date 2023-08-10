#!/bin/bash
set -eu
cd ../../tools
./reinstall-atclient.sh
cd ../packages/repl
rm -f build/CMakeCache.txt
cmake -S . -B build
sudo cmake --build build --target install
./bin/repl
