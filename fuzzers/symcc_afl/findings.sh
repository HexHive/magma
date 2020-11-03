#!/bin/bash

##
# Pre-requirements:
# - env SHARED: path to directory shared with host (to store results)
# + env MODE: which type of findings to list {crash, cov} (default: crash)
##

if [[ $MODE == crash ]]; then
    CRASH_DIRS=("$SHARED/findings/afl-master/crashes" "$SHARED/findings/symcc/crashes")
elif [[ $MODE == cov ]]; then
	CRASH_DIRS=("$SHARED/findings/afl-master/queue" "$SHARED/findings/symcc/queue")
fi

if [ ! -d "${CRASH_DIRS[0]}" ] && [ ! -d "${CRASH_DIRS[1]}" ]; then
    exit 1
fi

find ${CRASH_DIRS[@]} -type f -name 'id:*'
