#!/bin/bash

# this script creates a folder called install and will show you what kind of "mess" it makes. BY "mess" I mean what files it will install and where.

set -eu
sudo rm -f build/CMakeCache.txt
sudo rm -rf install
mkdir -p install
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./install
sudo cmake --build build --target install