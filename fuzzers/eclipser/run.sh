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

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1

"$FUZZER/afl/afl-fuzz" -m 100M -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    -S afl-worker $FUZZARGS -- "$OUT/afl/$PROGRAM" $ARGS 2>&1 &

FUZZER_PID=$!

while ps -p $FUZZER_PID > /dev/null 2>&1 && \
    [[ ! -f "$SHARED/findings/afl-worker/fuzzer_stats" ]]; do
    inotifywait -qq -t 1 -e create "$SHARED/findings" &> /dev/null
done

if [[ -f "$SHARED/findings/afl-worker/fuzzer_stats" ]]; then
    dotnet "$FUZZER/eclipser/build/Eclipser.dll" -p "$OUT/eclipser/$PROGRAM" \
        -s "$SHARED/findings" -i "$TARGET/corpus/$PROGRAM" \
        -o "$SHARED/findings/eclipser-output" \
        --arg eclipser-input -f eclipser-input -v 2 2>&1
fi
