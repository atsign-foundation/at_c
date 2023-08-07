#!/bin/bash
cmake -S ../ -B ../build
cd ../build
rm -f repl
make all
./repl
