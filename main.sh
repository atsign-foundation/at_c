#!/bin/bash
set -eu
# rm -rf build/
# mkdir -p build
rm -f build/main
cd build
sudo cmake -S .. -D BUILD_MBEDTLS=1
sudo make
./main
cd ..

