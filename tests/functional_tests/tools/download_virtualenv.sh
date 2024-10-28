#!/bin/bash

# 1. Check if curl is installed
if ! command -v curl &> /dev/null
then
    echo "curl could not be found, please install it."
    exit 1
fi

# 2. Download the docker-compose.yaml file, if it does not exist
url="https://github.com/atsign-foundation/at_server/raw/trunk/tools/virtualenv/docker-compose.yaml"
if [ ! -f docker-compose.yaml ]; then
    curl -L -o docker-compose.yaml $url
fi
