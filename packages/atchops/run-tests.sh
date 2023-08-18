#!/bin/bash
set -eu
# sudo rm -rf build
sudo cmake -S . -B build -DATCHOPS_BUILD_TESTS=ON -DATCHOPS_FETCH_MBEDTLS=ON -DCMAKE_INSTALL_PREFIX=./install
sudo rm -rf install
sudo cmake --build build --target all
cd build/tests
sudo ctest --output-on-failure -V
cd ../..