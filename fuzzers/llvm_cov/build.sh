#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

export CC="clang"
export CXX="clang++"

# compile standalone driver
$CC $CFLAGS -c "$FUZZER/src/StandaloneFuzzTargetMain.c" -fPIC \
    -o "$OUT/StandaloneFuzzTargetMain.o"
