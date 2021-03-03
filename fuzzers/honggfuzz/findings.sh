#!/bin/bash

##
# Pre-requirements:
# - env SHARED: path to directory shared with host (to store results)
# + env MODE: which type of findings to list {crash, cov} (default: crash)
##

if [[ $MODE == crash ]]; then
    CRASH_DIR="$SHARED/findings"
    CRASH_EXT=".fuzz"
elif [[ $MODE == cov ]]; then
    CRASH_DIR="$SHARED/findings/output"
    CRASH_EXT=".cov"
fi

if [ ! -d "$CRASH_DIR" ]; then
    exit 1
fi

find "$CRASH_DIR" -type f -name "*$CRASH_EXT"
