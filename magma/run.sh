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

# set default max log size to 1 MiB
LOGSIZE=${LOGSIZE:-$[1 << 20]}

export MONITOR="$SHARED/monitor"
mkdir -p "$MONITOR"

# change working directory to somewhere accessible by the fuzzer and target
cd "$SHARED"

find_triggered()
{
    ##
    # Pre-requirements:
    # - $1: human-readable monitor output
    ##
    awk '{print $5}' <<< "$1" | while read triggered; do
        if [ ! -z $triggered ] && [ $triggered -ne 0 ]; then
            awk '{print $1}' <<< "$1"
            return 1
        fi
    done
}

# prune the seed corpus for any fault-triggering test-cases
for seed in "$TARGET/corpus/$PROGRAM"/*; do
    out="$($OUT/monitor --fetch watch --dump human "$FUZZER/runonce.sh" "$seed")"
    code=$?

    bug=$(find_triggered "$out")
    is_triggered=$?

    if [ $is_triggered -ne 0 ]; then
        echo "$seed triggers $bug"
        rm "$seed"
    elif [ $code -ne 0 ]; then
        echo "$seed causes unexpected crash (exit code: $code)"
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
rm -f "$MONITOR/tmp"
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

echo "Campaign terminated at $(date '+%F %R')"

kill $(jobs -p)