#!/bin/bash
set -e

##
# Pre-requirements:
# - env MAGMA: path to Magma support files
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
##

MAGMA_STORAGE="$SHARED/canaries.raw"

$CC $CFLAGS -g -O0 -D"MAGMA_STORAGE=\"$MAGMA_STORAGE\"" "$MAGMA/src/monitor.c" \
    -I "$MAGMA/src/" -o "$OUT/monitor" $LDFLAGS $LIBS
