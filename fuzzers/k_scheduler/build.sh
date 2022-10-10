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

export PATH="/usr/local/go/bin:$PATH"
export GOPATH="$FUZZER/repo/go"
export PATH="$GOPATH/bin:$PATH"

export LLVM_CC_NAME="clang"
export LLVM_CXX_NAME="clang++"
export CC="gclang"
export CXX="gclang++"

export CFLAGS="-fsanitize-coverage=trace-pc-guard,no-prune -O2 -fno-omit-frame-pointer -gline-tables-only"
export CXXFLAGS="-fsanitize-coverage=trace-pc-guard,no-prune -O2 -fno-omit-frame-pointer -gline-tables-only"

# Build AFL runtime library and AFL driver
$CC -O2 -c -w "$FUZZER/repo/kscheduler/afl_integration/afl-2.52b_kscheduler/llvm_mode/afl-llvm-rt.o.c" -o afl-llvm-rt.o
$CXX -std=c++11 -O2 -c "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"
ar r "$OUT/afl_llvm_rt_driver.a" afl_driver.o afl-llvm-rt.o
rm afl_driver.o afl-llvm-rt.o
