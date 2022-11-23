#!/bin/bash

##
# Pre-requirements:
# - env SHARED: path to directory shared with host (to store results)
##

CRASH_DIR="$SHARED/findings/default/crashes"

if [ ! -d "$CRASH_DIR" ]; then
    exit 1
fi

find "$CRASH_DIR" -type f -name 'id:*'
