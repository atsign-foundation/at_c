#!/usr/bin/env bash

script_dir="$(dirname -- "$(readlink -f -- "$0")")"
package_dir="$script_dir/.."

echo "Starting file watcher"

inotifywait -mrqe modify,move,delete "$package_dir" --format "%e %f" --exclude build | while read change; do
  e=$(echo "$change" | cut -d' ' -f 1)
  f=$(echo "$change" | cut -d' ' -f 2-)
  if [[ "$f" = *.c ]] || [[ "$f" = *.h ]]; then
    echo "Detected change: $e - $f"
    echo "Compiling atclient"
    cmake -B "$package_dir/build" -S "$package_dir" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null
    echo "Building atclient"
    cmake --build "$package_dir/build" >/dev/null
    echo "Installing atclient"
    sudo cmake --build "$package_dir/build" --target install >/dev/null
    echo "Done rebuilding!"
  fi
done
