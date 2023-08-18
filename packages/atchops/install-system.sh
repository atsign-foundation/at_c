#!/bin/bash
set -eu
sudo rm -f build/CMakeCache.txt
cmake -S . -B build -DATCHOPS_FETCH_MBEDTLS=ON
sudo cmake --build build --target install