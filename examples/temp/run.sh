#!/bin/bash
cd ../../packages/atclient/tools
./install.sh
cd ../../../examples/temp
rm -rf build
sleep 1
cmake -S . -B build
cmake --build build
./build/main