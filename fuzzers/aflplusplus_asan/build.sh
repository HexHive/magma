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
export CC=clang-13
export CXX=clang++-13
export LLVM_CONFIG=llvm-config-13
export AFL_NO_X86=1
export PYTHON_INCLUDE=/
make -j$(nproc) || exit 1
make -C utils/aflpp_driver || exit 1

mkdir -p "$OUT/afl" "$OUT/cmplog"
