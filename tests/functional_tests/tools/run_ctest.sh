#!/bin/bash

# 
# Example usage
# tools/build.sh && tools/run_ctest.sh
#

set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"

cd ..

if [ ! -d "build" ] || [ -z "$(ls -A build)" ]; then
    echo "No build directory found, run ./tools/build.sh"
    exit 1
fi

ctest --test-dir build -VV --timeout 60
