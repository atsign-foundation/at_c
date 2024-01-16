#!/bin/bash
set -eu
cd ..
sudo cmake -S . -B build -DATCLIENT_FETCH_ATCHOPS=ON -DATCLIENT_FETCH_MBEDTLS=ON -DATCLIENT_BUILD_TESTS=ON
sudo cmake --build build --target install
