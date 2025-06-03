#!/bin/sh
# This PATCH_COMMAND script performs the following:
# Replaces the following line in the cJSON CMakeLists.txt:
# `cmake_minimum_required(VERSION 3.0)`
# With the line:
# `cmake_minimum_required(VERSION 3.24)`
# This allows us to build it with CMake v4
if [ "$(uname)" = 'Darwin' ]; then
  # Unix sed
  sed -e '2s/0/24/' -i '' CMakeLists.txt
else
  # GNU sed
  sed -e '2s/0/24/' -i CMakeLists.txt
fi
