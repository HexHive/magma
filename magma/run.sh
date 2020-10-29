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
# - env POLL: time (in seconds) to sleep between polls
# - env TIMEOUT: time to run the campaign
# - env MAGMA: path to Magma support files
# + env LOGSIZE: size (in bytes) of log file to generate (default: 1 MiB)
##

# set default max log size to 1 MiB
LOGSIZE=${LOGSIZE:-$[1 << 20]}

export MONITOR="$SHARED/monitor"
mkdir -p "$MONITOR"

# change working directory to somewhere accessible by the fuzzer and target
cd "$SHARED"

# prune the seed corpus for any fault-triggering test-cases
for seed in "$TARGET/corpus/$PROGRAM"/*; do
    out="$("$MAGMA"/runonce.sh "$seed")"
    code=$?

    if [ $code -ne 0 ]; then
        echo "$seed: $out"
        rm "$seed"
    fi
done

shopt -s nullglob
seeds=("$1"/*)
shopt -u nullglob
if [ ${#seeds[@]} -eq 0 ]; then
    echo "No seeds remaining! Campaign will not be launched."
    exit 1
fi


# launch the fuzzer in parallel with the monitor
rm -f "$MONITOR/tmp"*
polls=("$MONITOR"/*)
if [ ${#polls[@]} -eq 0 ]; then
    counter=0
else
    timestamps=($(sort -n < <(basename -a "${polls[@]}")))
    last=${timestamps[-1]}
    counter=$(( last + POLL ))
fi

while true; do
    "$OUT/monitor" --dump row > "$MONITOR/tmp"
    if [ $? -eq 0 ]; then
        mv "$MONITOR/tmp" "$MONITOR/$counter"
    else
        rm "$MONITOR/tmp"
    fi
    counter=$(( counter + POLL ))
    sleep $POLL
done &

echo "Campaign launched at $(date '+%F %R')"

timeout $TIMEOUT "$FUZZER/run.sh" | \
    multilog n2 s$LOGSIZE "$SHARED/log"

if [ -f "$SHARED/log/current" ]; then
    cat "$SHARED/log/current"
fi

echo "Campaign terminated at $(date '+%F %R')"

kill $(jobs -p)
