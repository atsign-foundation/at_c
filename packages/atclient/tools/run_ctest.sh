#!/bin/bash
set -eu
cd ..
# sudo rm -rf build
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON
cmake --build build --target all
cd build/tests
ctest -V
