#!/usr/bin/env bash

if [ -z "$HOME" ]; then
  echo HOME environment variable not set

fi

dest="$HOME/Documents/Arduino/libraries/atsdk"

echo This will delete the existing library at:
echo "  $dest"
printf 'Type "y" to confirm: '

read -n 1 response
echo

if ! [ "$response" = 'y' ]; then
  echo "Canceled operation"
  exit 0
fi

script_dir="$(dirname -- "$(readlink -f -- "$0")")"

rm -rf $dest
cp -r $script_dir $dest
