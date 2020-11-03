#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where minimized corpus is stored
# - env SHARED: path to directory shared with host (original corpus)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

# replace AFL-style input file parameter with honggfuzz-style one
ARGS="${ARGS/@@/___FILE___}"

"$FUZZER/repo/honggfuzz" --minimize --input "$SHARED" --output "$OUT" \
    -- "$OUT/$PROGRAM" $ARGS 2>&1
