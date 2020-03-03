#!/bin/bash
set -e

##
# Pre-requirements:
# - env MAGMA: path to Magma support files
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
##

MAGMA_STORAGE="$SHARED/canaries.raw"

$CC $CFLAGS -D"MAGMA_STORAGE=\"$MAGMA_STORAGE\"" -c "$MAGMA/src/storage.c" \
    -fPIC -I "$MAGMA/src/" -o "$OUT/pre_storage.o" $LDFLAGS

$CC $CFLAGS -g -O0 -D"MAGMA_STORAGE=\"$MAGMA_STORAGE\"" "$MAGMA/src/monitor.c" \
    "$OUT/pre_storage.o" -I "$MAGMA/src/" -o "$OUT/monitor" $LDFLAGS $LIBS

rm "$OUT/pre_storage.o"
