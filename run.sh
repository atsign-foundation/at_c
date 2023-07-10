#!/bin/bash
# python3 tool.py -p desktop -f mbedtls clean
python3 tool.py -p desktop -f mbedtls build
python3 tool.py -p desktop -f mbedtls test