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

mkdir -p "$SHARED/bb-findings" "$SHARED/func-findings" "$SHARED/loop-findings"

export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_DRIVER_DONT_DEFER=1

"$FUZZER/repo/bb_metric/afl-fuzz" -s -m none -t 1000+ \
    -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/bb-findings" \
    $FUZZARGS -- "$OUT/bb_metric/$PROGRAM" $ARGS 2>&1 &
sleep 3s

"$FUZZER/repo/func_metric/afl-fuzz" -s -m none -t 1000+ \
    -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/func-findings" \
    $FUZZARGS -- "$OUT/func_metric/$PROGRAM" $ARGS 2>&1 &
sleep 3s

"$FUZZER/repo/loop_metric/afl-fuzz" -s -m none -t 1000+ \
    -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/loop-findings" \
    $FUZZARGS -- "$OUT/loop_metric/$PROGRAM" $ARGS 2>&1
