#!/bin/bash
set -eu
FULL_PATH_TO_SCRIPT="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIRECTORY="$(dirname "$FULL_PATH_TO_SCRIPT")"
cd "$SCRIPT_DIRECTORY"

./build_tests.sh

cd ..

run_test() {
  cd "$SCRIPT_DIRECTORY"/../build/"$1"
  ctest --output-on-failure --timeout 2
}

run_test 'packages/atchops/tests'
run_test 'packages/atclient/tests'
run_test 'packages/atcommons/tests'