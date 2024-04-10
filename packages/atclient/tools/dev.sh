#!/usr/bin/env bash

script_dir="$(dirname -- "$(readlink -f -- "$0")")"
package_dir="$script_dir/.."
while true; do
  # list for changes in the atclient directory
  inotifywait -e modify,create,delete,move -r "$package_dir"
  # rebuild the project
  echo "Rebuilding atclient"
  cmake -B "$package_dir/build" -S "$package_dir" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  cmake --build "$package_dir/build" --target install
  echo "Done rebuilding!"
done
