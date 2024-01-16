#!/bin/bash
set -eu
sudo rm -rf /usr/local/include/atclient
sudo rm -rf /usr/local/include/atchops
cd ../../packages/atclient
sudo cmake -S . -B build -DATCLIENT_FETCH_MBEDTLS=OFF -DATCLIENT_FETCH_ATCHOPS=ON
sudo cmake --build build --target install
cd ../../examples/at_talk
sudo cmake -S . -B build
sudo cmake --build build --target clean
sudo cmake --build build --target all
echo "Running main:"
echo ""
echo ""
cd build && ./main
cd ..
