#!/bin/bash
set -eu
sudo rm -f build/CMakeCache.txt
sudo rm -rf install
mkdir -p install
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./install -DATCHOPS_FETCH_MBEDTLS=ON
cmake --build build --target install/local