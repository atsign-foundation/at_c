#!/bin/bash
set -eu
cd ..
sudo rm -rf build/tests
cmake -S . -B build -DATCHOPS_BUILD_TESTS=ON
cmake --build build --target all
cd build/tests
ctest -V
