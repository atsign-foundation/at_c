#!/bin/bash
set -eu
cd ..
sudo cmake -S . -B build -DATCLIENT_BUILD_TESTS=OFF
sudo cmake --build build --target install
