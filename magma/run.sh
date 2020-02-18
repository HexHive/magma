#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env POLL: time (in seconds) to sleep between polls
# - env TIMEOUT: time to run the campaign
# + env LOGSIZE: size (in bytes) of log file to generate (default: 1 MiB)
##

if ! rm -rf "$SHARED"/*; then
    echo "Failed to clean findings directory!"
    exit 1
fi

# set default max log size to 1 MiB
LOGSIZE=${LOGSIZE:-$[1 << 20]}

export MONITOR="$SHARED/monitor"
mkdir -p "$MONITOR"

# change working directory to somewhere accessible by the fuzzer and target
cd "$SHARED"

# prune the seed corpus for any fault-triggering test-cases
for seed in "$TARGET/corpus/$PROGRAM"/*; do
    if ! "$FUZZER/runonce.sh" "$seed"; then
        rm "$seed"
    fi
done

# launch the fuzzer in parallel with the monitor
counter=0
while true; do
    "$OUT/monitor" > "$MONITOR/tmp"
    if [ $? -eq 0 ]; then
        mv "$MONITOR/tmp" "$MONITOR/$counter"
    else
        rm "$MONITOR/tmp"
    fi
    counter=$(( counter + POLL ))
    sleep $POLL
done &

timeout $TIMEOUT "$FUZZER/run.sh" | \
    multilog n2 s$LOGSIZE "$SHARED/log"

kill $(jobs -p)