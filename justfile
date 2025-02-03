alias build := build-debug
alias test := test-all
alias unit := test-unit
alias func := test-func
alias memd := memcheck-docker
alias vald := valgrind-docker

set dotenv-filename := "just.env"
set dotenv-load

postfix := quote(os() + "-" + arch())
debug_dir := quote(justfile_directory() / "build/debug-") + postfix
release_dir := quote(justfile_directory() / "build/release-") + postfix
test_dir := quote(justfile_directory() / "build/test-") + postfix
unit_dir := quote(justfile_directory() / "build/unit-") + postfix
func_dir := quote(justfile_directory() / "build/func-") + postfix
memcheck_dir := quote(justfile_directory() / "build/memcheck-") + postfix

# SETUP COMMANDS

setup: configure-test-all
  [ -f "$PWD/compile_commands.json" ] && rm $PWD/compile_commands.json || true
  ln -s {{test_dir}}/compile_commands.json $PWD
  [ -f "$PWD/compile_commands.json" ] && rm $PWD/tests/compile_commands.json || true
  ln -s {{test_dir}}/compile_commands.json $PWD/tests

setup-valgrind:
  docker build --platform linux/amd64 -t atc-memcheck-docker:latest -f $PWD/valgrind.Dockerfile $PWD

clean:
  rm -rf $PWD/build
  rm $PWD/compile_commands.json
  rm $PWD/tests/compile_commands.json

# INSTALL COMMANDS

install: build-debug
  cmake: --build {{debug_dir}} --target install

# BUILD COMMANDS

package-static:
  cmake --workflow --preset package-static

package-source:
  cmake --workflow --preset package-source

build-debug: configure-debug
  cmake --build {{debug_dir}}

build-release: configure-release
  cmake --build {{release_dir}}

build-test-unit: configure-test-unit
  cmake --build {{unit_dir}}

build-test-func: configure-test-func
  cmake --build {{func_dir}}

build-test-all: configure-test-all
  cmake --build {{test_dir}}

build-test-memcheck: configure-test-memcheck
  cmake --build {{memcheck_dir}}

# TEST COMMANDS

test-unit +ARGS='': build-test-unit
  ctest --test-dir {{unit_dir}} {{ARGS}}

test-func +ARGS='': build-test-func
  ctest --test-dir {{func_dir}} {{ARGS}}

test-all +ARGS='': build-test-all
  ctest --test-dir {{test_dir}} {{ARGS}}

memcheck +ARGS='': build-test-memcheck
  ctest -T memcheck --test-dir {{memcheck_dir}} {{ARGS}}

memcheck-docker +ARGS='':
  docker run --rm --platform linux/amd64 \
  --mount type=bind,src=$PWD,dst=/mnt/at_c \
  --mount type=bind,src=$HOME/.atsign/keys,dst=/root/.atsign/keys \
  atc-memcheck-docker:latest \
  just memcheck {{ARGS}}

valgrind-docker:
  docker run --rm --platform linux/amd64 \
  -ti \
  --mount type=bind,src=$PWD,dst=/mnt/at_c \
  --mount type=bind,src=$HOME/.atsign/keys,dst=/root/.atsign/keys \
  atc-memcheck-docker:latest  \
  /bin/bash

# CONFIGURE COMMANDS

configure-debug:
  cmake -B {{debug_dir}} \
    -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_INSTALL_PREFIX="$HOME/.local/" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_MEMCHECK=OFF

configure-release:
  cmake -B {{release_dir}} \
    -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS=OFF \
    -DATSDK_MEMCHECK=OFF

configure-test-unit:
  cmake -B {{unit_dir}} \
    -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error " \
    -DATSDK_BUILD_TESTS="unit" \
    -DATSDK_MEMCHECK=OFF \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\""

configure-test-func:
  cmake -B {{func_dir}} \
    -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error" \
    -DATSDK_BUILD_TESTS="func" \
    -DATSDK_MEMCHECK=OFF \
    -DATDIRECTORY_HOST="\"$ATDIRECTORY_HOST\"" \
    -DATDIRECTORY_PORT=$ATDIRECTORY_PORT \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\"" \
    -DFIRST_ATSIGN_ATSERVER_HOST="\"$FIRST_ATSIGN_ATSERVER_HOST\"" \
    -DFIRST_ATSIGN_ATSERVER_PORT=$FIRST_ATSIGN_ATSERVER_PORT \
    -DSECOND_ATSIGN_ATSERVER_HOST="\"$SECOND_ATSIGN_ATSERVER_HOST\"" \
    -DSECOND_ATSIGN_ATSERVER_PORT=$SECOND_ATSIGN_ATSERVER_PORT

configure-test-all:
  cmake -B {{test_dir}} \
    -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=c99 -Wno-error " \
    -DATSDK_BUILD_TESTS=ON \
    -DATSDK_MEMCHECK=OFF \
    -DATDIRECTORY_HOST="\"$ATDIRECTORY_HOST\"" \
    -DATDIRECTORY_PORT=$ATDIRECTORY_PORT \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\"" \
    -DFIRST_ATSIGN_ATSERVER_HOST="\"$FIRST_ATSIGN_ATSERVER_HOST\"" \
    -DFIRST_ATSIGN_ATSERVER_PORT=$FIRST_ATSIGN_ATSERVER_PORT \
    -DSECOND_ATSIGN_ATSERVER_HOST="\"$SECOND_ATSIGN_ATSERVER_HOST\"" \
    -DSECOND_ATSIGN_ATSERVER_PORT=$SECOND_ATSIGN_ATSERVER_PORT

configure-test-memcheck:
  cmake -B {{memcheck_dir}} \
    -S $PWD \
    -G "$GENERATOR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=$C_COMPILER \
    -DCMAKE_C_FLAGS="-std=gnu99 -Wno-error" \
    -DATSDK_BUILD_TESTS=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DATSDK_MEMCHECK=ON \
    -DFIRST_ATSIGN="\"$FIRST_ATSIGN\"" \
    -DSECOND_ATSIGN="\"$SECOND_ATSIGN\""

# DIAGNOSTIC COMMANDS

show-env:
  echo "$C_COMPILER"
  echo "$GENERATOR"
  echo "$ATDIRECTORY_HOST"
  echo "$ATDIRECTORY_PORT"
  echo "$FIRST_ATSIGN"
  echo "$FIRST_ATSIGN_ATSERVER_HOST"
  echo "$FIRST_ATSIGN_ATSERVER_PORT"
  echo "$SECOND_ATSIGN"
  echo "$SECOND_ATSIGN_ATSERVER_HOST"
  echo "$SECOND_ATSIGN_ATSERVER_PORT"
