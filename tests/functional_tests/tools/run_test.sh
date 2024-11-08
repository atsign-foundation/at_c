#!/bin/bash

# 
# Example usage
# tools/build.sh && tools/run_test.sh test_atclient_connection
# 

set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"
cd ..

if [ ! -d "build" ]; then
    echo "No build directory found, run ./tools/build.sh"
    exit 1    
fi

./build/$1
