#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env FUZZARGS: extra arguments to pass to the fuzzer
##

mkdir -p "$SHARED/findings" "$SHARED/output"

# replace AFL-style input file parameter with honggfuzz-style one
ARGS="${ARGS/@@/___FILE___}"

"$FUZZER/repo/honggfuzz" -n 1 -z --input "$TARGET/corpus/$PROGRAM" \
    --output "$SHARED/output" --workspace "$SHARED/findings" \
    $FUZZARGS -- "$OUT/$PROGRAM" $ARGS 2>&1
