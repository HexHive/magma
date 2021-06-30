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

export GOPATH="$FUZZER/repo/go"
export PATH="$GOPATH/bin:$PATH"

export CC="gclang"
export CXX="gclang++"

export CFLAGS="$CFLAGS -fno-discard-value-names"
export CXXFLAGS="$CXXFLAGS -fno-discard-value-names"

# compile standalone driver
$CC $CFLAGS -c "$FUZZER/src/StandaloneFuzzTargetMain.c" -fPIC \
    -o "$OUT/StandaloneFuzzTargetMain.o"
