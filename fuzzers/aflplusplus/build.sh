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

cd "$FUZZER/repo"
export CC=clang
export AFL_NO_X86=1
export PYTHON_INCLUDE=/
make -j $(nproc) source-only
make -C examples/aflpp_driver

mkdir -p "$OUT/afl" "$OUT/cmplog"
