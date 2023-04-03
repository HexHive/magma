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

if nm "$OUT/afl/$PROGRAM" | grep -E '^[0-9a-f]+\s+[Ww]\s+main$'; then
    ARGS="-"
fi

mkdir -p "$SHARED/findings"

flag_cmplog=(-l2 -c "$OUT/cmplog/$PROGRAM")

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_NO_UI=1
export AFL_MAP_SIZE=256000
export AFL_DRIVER_DONT_DEFER=1
export AFL_IGNORE_UNKNOWN_ENVS=1
export AFL_FAST_CAL=1
export AFL_NO_WARN_INSTABILITY=1
export AFL_DISABLE_TRIM=1

for i in $OUT/*.dict $OUT/*.dic $OUT/afl/*.dict $OUT/afl/*.dic; do
  test -f "$i" && DICT="$DICT -x $i"
done

ulimit -c unlimited
cd $SHARED

"$FUZZER/repo/afl-fuzz" -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    "${flag_cmplog[@]}" $DICT \
    $FUZZARGS -- "$OUT/afl/$PROGRAM" $ARGS 2>&1
