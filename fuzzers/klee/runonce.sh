#!/bin/bash -e

##
# Pre-requirements:
# - $1: path to test case
# - $2..N: KLEE runtime arguments (e.g., --sym-args N)
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

args="${ARGS/@@/"'$1'"}"
if [ -z "$args" ]; then
    args="'$1'"
fi

klee --libc=uclibc --posix-runtime "$OUT/$PROGRAM.bc" ${@:2} $args