#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env OUT: path to directory where artifacts are stored
# - env CORPUS_IN: path to directory shared with host (original corpus)
# - env CORPUS_OUT: path to directory where minimized corpus is stored
##

export AFL_PATH="$FUZZER/afl"
"$FUZZER/afl/afl-cmin" -m 100 -t 100 -i "$CORPUS_IN" -o "$CORPUS_OUT/tmp" \
    -- "$OUT/$PROGRAM" $ARGS 2>&1

find "$CORPUS_OUT/tmp" -maxdepth 1 -type f -exec mv {} "$CORPUS_OUT" \;
rm -rf "$CORPUS_OUT/tmp"