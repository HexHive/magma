#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/eclipser" ] || [ ! -d "$FUZZER/afl" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

# build eclipser
(
    cd "$FUZZER/eclipser"
    make -j $(nproc)

    mkdir -p "$OUT/eclipser"
    clang++ $CXXFLAGS -std=c++11 -c "$FUZZER/eclipser/standalone_driver.cpp" -fPIC -o "$OUT/eclipser/standalone_driver.o"
)

# build AFL
(
    cd "$FUZZER/afl"
    CC=clang make -j $(nproc)
    CC=clang make -j $(nproc) -C llvm_mode

    mkdir -p "$OUT/afl"
    clang++ $CXXFLAGS -std=c++11 -c "$FUZZER/afl/afl_driver.cpp" -fPIC -o "$OUT/afl/afl_driver.o"
    ar r "$OUT/afl/libafl.a" "$OUT/afl/afl_driver.o" "$FUZZER/afl/afl-llvm-rt.o"
)
