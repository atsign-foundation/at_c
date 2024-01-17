#!/bin/bash
set -eu
cd ..
sudo rm -rf build
sudo cmake -S . -B build -DATCLIENT_BUILD_TESTS=OFF
sudo cmake --build build --target install
