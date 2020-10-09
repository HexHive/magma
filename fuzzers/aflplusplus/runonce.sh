#!/bin/bash -e

##
# Pre-requirements:
# - $1: path to test case
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

export TIMELIMIT=0.1s

run_limited()
{
    ${@:1}
    test $? -lt 128
}
export -f run_limited

args="${ARGS/@@/"'$1'"}"
if [ -z "$args" ]; then
    args="'$1'"
fi

timeout -s KILL --preserve-status $TIMELIMIT bash -c \
    "run_limited '$OUT/afl/$PROGRAM' $args"
