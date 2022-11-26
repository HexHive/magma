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

cd "$OUT/${PROGRAM}_out"
python3 "$FUZZER/repo/kscheduler/afl_integration/build_example/gen_dyn_weight.py" 2>&1 &
sleep 5s

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_NO_UI=1
export AFL_DRIVER_DONT_DEFER=1

"$FUZZER/repo/kscheduler/afl_integration/afl-2.52b_kscheduler/afl-fuzz" \
    -m 100M -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    $FUZZARGS -- "$OUT/$PROGRAM" $ARGS 2>&1
