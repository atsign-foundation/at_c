#!/bin/bash

sudo rm -f $(cat ../packages/atchops/build/install_manifest.txt)
sudo rm -f $(cat ../packages/atclient/build/install_manifest.txt)

# directories
sudo rm -rf /usr/local/lib/cmake/atclient /usr/local/lib/cmake/atchops
sudo rm -rf /usr/local/include/atclient /usr/local/include/atchops /usr/local/include/psa /usr/local/include/mbedtls


