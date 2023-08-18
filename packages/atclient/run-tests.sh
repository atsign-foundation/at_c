#!/bin/bash
set -eu
cmake -S . -B build -DATCLIENT_BUILD_TESTS=ON -DATCLIENT_FETCH_MBEDTLS=OFF -DATCLIENT_FETCH_ATCHOPS=OFF
sudo cmake --build build --target all
cd build/tests
ctest --output-on-failure
cd ../..