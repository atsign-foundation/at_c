#!/bin/bash
set -eu
sudo rm -f build/CMakeCache.txt
cmake -S . -B build
sudo cmake --build build --target install