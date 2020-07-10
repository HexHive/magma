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
CC=clang make -j $(nproc) source-only

# compile afl_driver.cpp
mkdir -p "$OUT/afl" "$OUT/cmplog"

(
    export AFL_LLVM_INSTRUMENT=CLASSIC
    export AFL_LLVM_CTX=1
    export AFL_LLVM_SKIP_NEVERZERO=1
    "./afl-clang-fast++" $CXXFLAGS -std=c++11 -c "afl_driver.cpp" \
        -fPIC -o "$OUT/afl/afl_driver.o"
)

(
    export AFL_LLVM_INSTRUMENT=CLASSIC
    export AFL_LLVM_CTX=1
    export AFL_LLVM_SKIP_NEVERZERO=1
    export AFL_LLVM_CMPLOG=1
    "./afl-clang-fast++" $CXXFLAGS -std=c++11 -c "afl_driver.cpp" \
        -fPIC -o "$OUT/cmplog/afl_driver.o"
)
