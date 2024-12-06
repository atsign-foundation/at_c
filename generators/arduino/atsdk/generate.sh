#!/usr/bin/env bash

# Note about template naming:
# They will be named as *.[c|h]template so that the Arduino
# compiler won't try to compile them

script_dir="$(dirname -- "$(readlink -f -- "$0")")"
if [ -z "$script_dir" ]; then
  echo "Can't resolve current script directory"
  exit 1
fi
src_base=$script_dir/src

# state to track packages which need headers fixed
packages=()
# recurse_packages=()

# Macos resilient sed -i
sedi() {
  if [ $(uname) = 'Darwin' ]; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

# Function which removes all the files
# this is always run before generating
clean() {
  [ -d $src_base ] && rm -r $src_base
}

# Bootstraps generated files and folders
bootstrap() {
  mkdir -p $src_base
  echo "*" >$src_base/.gitignore
}

# Generic function which symbollically links package files
# into a valid Arduino library format
# Arduino libraries only have a notion of public headers
# this will only link headers internally
# (unless the inc_dst is set to '.')
gen_src() {
  if [ $# -lt 4 ]; then
    echo "Error not enough args passed to gen src"
    return 1
  fi
  # Required parameters
  # Name of the dependency
  local name="$1"
  # Base path of where the dependency is located
  local base_path="$2"
  # Path containing all of the source files
  local src_path="$base_path/$3"
  # Path containing the header files
  local inc_path="$base_path/$4"
  # Location to place the header files
  # passing '.' will make them public
  local inc_dst="$src_base/$name"

  local override_func="$5"

  # append to array of packages to fix later
  packages+=("$name")

  # source files
  local src_files=$(
    cd "$src_path" &&
      ls *.c
  )
  for sf in $src_files; do
    if [ -n "$exclude_src" ] && [ "$exclude_src" = "$sf" ]; then
      continue
    fi
    # prefix source names with the package name to avoid collisions
    cp "$src_path/$sf" "$src_base/${name}_$sf"
  done
  # include files
  local inc_files=$(
    cd "$inc_path" &&
      ls *.h
  )
  mkdir -p "$inc_dst"
  for if in $inc_files; do
    cp "$inc_path/$if" "$inc_dst/$if"
  done
  if [ -n "$override_func" ]; then
    $override_func
  fi
}

# convert everything to a relative import... because arduino
fix_rel_headers() {
  # modify .h files to use relative path
  for outer in ${packages[@]}; do
    local includes=$(
      cd "$src_base/$outer" &&
        ls *.h
    )
    for f in $includes; do
      for inner in ${packages[@]}; do
        # all expressions match: ^#include [<\"]$inner/(.*\.h)[>\"]
        # which finds an include which matches <$inner/something.h> or "$inner/something.h"
        # and stores something.h in \1 (something.h is a wildcard .h file)
        local match="^#include [<\"]$inner/(.*\.h)[>\"]"
        local replace=""

        if [ "$inner" = "$outer" ]; then
          # e.g. <atclient/atclient.h> -> "atclient.h" when in package atclient
          replace='#include "\1"'
        else
          # e.g. <atlogger/atlogger.h> -> "../atlogger/atlogger.h" when in package atclient
          replace="#include \"../$inner/\\1\""
        fi
        sedi -E -e "s@$match@$replace@" "$src_base/$outer/$f"
      done
    done
  done
  # handle nested subfolders
  for package in ${recurse_packages[@]}; do
    local rel_base="$src_base/$package"
    local dirs=$(
      cd "$rel_base" &&
        find . -type d
    )
    for outer in ${dirs[@]}; do
      if [ $outer = '.' ]; then
        continue
      fi
      # strip ./ prefix
      outer="${outer:2}"

      local includes=$(
        cd $rel_base/$outer &&
          ls *.h
      )
      for f in $includes; do
        for inner in ${dirs[@]}; do
          local match=""
          local prefix=""
          if [ $inner = '.' ]; then
            match="^#include \"([a-zA-Z_-]*.h)\""
          else
            # strip ./ prefix
            inner="${inner:2}"
            match="^#include [<\"]$inner/([a-zA-Z_-]*.h)[>\"]"
            # count slashes in outer as a ../
            local only="${outer//[^\/]/}"
            for i in $(seq $((${#only} + 1))); do
              prefix="../$prefix"
            done
            # append the inner prefix
            prefix="$prefix$inner/"
          fi
          local replace="#include \"$prefix\\1\""
          sedi -E -e "s@$match@$replace@" "$rel_base/$outer/$f"
          # echo "$rel_base/$outer/$f"
        done
      done
    done
  done
  # modify .c files to use relative path
  local src_files=$(
    cd "$src_base" &&
      ls *.c
  )
  for f in $src_files; do
    for p in ${packages[@]}; do
      # all expressions match: ^#include [<\"]$inner/(.*\.h)[>\"]
      # which finds an include which matches <$inner/something.h> or "$inner/something.h"
      # and stores something.h in \1 (something.h is a wildcard .h file)
      local match="^#include [<\"]$p/(.*\.h)[>\"]"
      # e.g. <atlogger/atlogger.h> -> "atlogger/atlogger.h" when in package atclient
      local replace="#include \"$p/\\1\""
      sedi -E -e "s@$match@$replace@" "$src_base/$f"
    done
    # fi
  done
}

public_headers() {
  cat "$script_dir/atsdk.htemplate" >>$src_base/atsdk.h
  for d in ${packages[@]}; do
    local includes=$(
      cd "$src_base/$d" &&
        ls *.h
    )
    for f in $includes; do

      echo "#include \"$d/$f\" // IWYU pragma: export" >>$src_base/atsdk.h
    done
  done
  cp "$script_dir/atsdk_cjson.htemplate" $src_base/atsdk_cjson.h
  cp "$script_dir/atsdk_cjson.ctemplate" $src_base/atsdk_cjson.c
  cp "$script_dir/atsdk_atsdk.cpptemplate" $src_base/atsdk_atsdk.cpp
}

echo "Cleaning generated files and folders"
clean

if [ "$1" = "--clean" ]; then
  unset clean
  unset gen_src
  unset public_headers
  exit 0
fi

echo "Bootstrapping project"
bootstrap

echo "Generating Arduino library structure"

# locally available packages
gen_src atlogger "$script_dir/../../../packages/atlogger" \
  src include/atlogger
gen_src atchops "$script_dir/../../../packages/atchops" \
  src include/atchops
gen_src atcommons "$script_dir/../../../packages/atcommons" \
  src include/atcommons
gen_src atclient "$script_dir/../../../packages/atclient" \
  src include/atclient

# generate public includes
echo "Generating public header files"
public_headers

echo "Fixing all includes to be relative"
fix_rel_headers

echo "Done generating Arduino library"

# functions
unset sedi
unset clean
unset gen_src
unset public_headers
unset fix_rel_headers

# global variables
unset script_dir
unset src_base
unset packages
unset recurse_packages
