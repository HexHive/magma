#!/bin/bash

##
# Pre-requirements:
# - env SHARED: path to directory shared with host (to store results)
##

CRASH_DIRS=("$SHARED/findings/afl-master/crashes" "$SHARED/findings/symcc/crashes")

if [ ! -d "${CRASH_DIRS[0]}" ] && [ ! -d "${CRASH_DIRS[1]}" ]; then
    exit 1
fi

find ${CRASH_DIRS[@]} -type f -name 'id:*'
