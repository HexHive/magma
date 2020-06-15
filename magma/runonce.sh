#!/bin/bash

##
# Pre-requirements:
# - $1: path to test case
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
##

find_triggered()
{
    ##
    # Pre-requirements:
    # - $1: human-readable monitor output
    ##
    echo "$1" | while read line; do
        triggered=$(awk '{print $5}' <<< "$line")
        if [ ! -z $triggered ] && [ $triggered -ne 0 ]; then
            awk '{print $1}' <<< "$line"
            return 1
        fi
    done
}

cd "$SHARED"
cp --force "$1" "$SHARED/runonce.tmp"
out="$($OUT/monitor --fetch watch --dump human "$FUZZER/runonce.sh" "$SHARED/runonce.tmp")"
exit_code=$?
bug=$(find_triggered "$out")
is_triggered=$?

msg="exit_code $exit_code"

if [ $is_triggered -ne 0 ]; then
    msg="$msg bug $bug"
fi

echo "$msg"
rm "$SHARED/runonce.tmp"

if [ $is_triggered -ne 0 ] || [ $exit_code -ne 0 ]; then
    exit 1
fi
