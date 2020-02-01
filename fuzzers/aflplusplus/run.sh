#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

# Clean corpus dir from crashing cases
for seed in "$TARGET/corpus/$PROGRAM"/*; do
    if ! "$OUT/afl/$PROGRAM" "$seed"; then
        rm "$seed"
    fi
done

mkdir -p "$SHARED/findings"

#flag_cmplog="-c "$OUT/cmplog/$PROGRAM""

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
"$FUZZER/repo/afl-fuzz" -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    $flag_cmplog -m none -p fast \
    -- "$OUT/afl/$PROGRAM" "$ARGS" @@  2>&1 | \
    tee "$SHARED/fuzzer.log"
