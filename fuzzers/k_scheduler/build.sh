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

cd "$FUZZER/repo/kscheduler/afl_integration/afl-2.52b_kscheduler"
make clean
make -j $(nproc)
make -j $(nproc) -C llvm_mode ../afl-llvm-rt.o
cp afl-llvm-rt.o $OUT

export PATH="/usr/local/go/bin:$PATH"
export GOPATH="$FUZZER/repo/go"
export PATH="$GOPATH/bin:$PATH"

export CFLAGS="$CFLAGS -O2 -fsanitize-coverage=trace-pc-guard,no-prune -fno-omit-frame-pointer -gline-tables-only"
export CXXFLAGS="$CXXFLAGS -O2 -fsanitize-coverage=trace-pc-guard,no-prune -fno-omit-frame-pointer -gline-tables-only"

export LLVM_CC_NAME="clang"
export LLVM_CXX_NAME="clang++"
export CC="gclang"
export CXX="gclang++"

# Build AFL driver
$CXX -std=c++11 -c \
    "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp" \
    -o "$OUT/afl_driver.o"
