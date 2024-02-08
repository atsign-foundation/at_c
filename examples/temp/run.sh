#!/bin/bash
cd ../../packages/atclient/tools
./install.sh
cd ../../../examples/temp
rm -f build/main
cmake -S . -B build
cmake --build build
./build/main