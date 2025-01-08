#!/bin/bash
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"

if [ ! -f "docker-compose.yaml" ]; then
    echo "Error: docker-compose.yml not found in $SCRIPT_DIRECTORY. See download_virtualenv.sh"
    exit 1
fi

docker-compose down
