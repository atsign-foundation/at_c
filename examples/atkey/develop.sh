#!/bin/bash
set -eu
sudo rm -rf /usr/local/include/atclient
sudo rm -rf /usr/local/include/atchops
cd ../../packages/atclient
cmake -S . -B build -DATCLIENT_FETCH_MBEDTLS=OFF -DATCLIENT_FETCH_ATCHOPS=ON
sudo cmake --build build --target install
cd ../../examples/atkey
cmake -S . -B build
cmake --build build --target clean
cmake --build build --target all
echo "Running main:"
echo ""
echo ""
cd build
./exec
cd ..
