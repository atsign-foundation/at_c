#!/bin/bash
set -eu
cd ..
sudo cmake -S . -B build -DATCLIENT_FETCH_ATCHOPS=ON -DATCLIENT_FETCH_MBEDTLS=ON -DATCLIENT_BUILD_TESTS=OFF
sudo cmake --build build --target install
