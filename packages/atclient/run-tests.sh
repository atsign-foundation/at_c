#!/bin/bash
set -eu
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON
sudo cmake --build build --target all
cd build/tests
ctest --output-on-failure
cd ../..