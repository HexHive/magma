#!/bin/bash

##
# Pre-requirements:
# - env SHARED: path to directory shared with host (to store results)
# + env MODE: which type of findings to list {crash, cov} (default: crash)
##

if [[ $MODE == crash ]]; then
    CRASH_DIR="$SHARED/findings/crashes"
elif [[ $MODE == cov ]]; then
    CRASH_DIR="$SHARED/findings/queue"
fi

if [ ! -d "$CRASH_DIR" ]; then
    exit 1
fi

find "$CRASH_DIR" -type f -name 'id:*'
