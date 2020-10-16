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

mkdir -p "$SHARED/findings"

"$OUT/$PROGRAM" -rss_limit_mb=100 -entropic=1 \
	-fork=1 -ignore_timeouts=1 -ignore_crashes=1 -ignore_ooms=1 \
	-artifact_prefix="$SHARED/findings/" $FUZZARGS \
    "$TARGET/corpus/$PROGRAM" $ARGS
