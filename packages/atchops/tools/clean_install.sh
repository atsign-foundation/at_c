#!/bin/bash
set -eu
cd ..
sudo rm -rf build
cmake -S . -B build -DATCHOPS_BUILD_TESTS=OFF
sudo cmake --build build --target install