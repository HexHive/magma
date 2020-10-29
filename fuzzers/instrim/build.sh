#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/afl" ] || [ ! -d "$FUZZER/instrim" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

# build InsTrim
(
    cd "$FUZZER/instrim"
    mkdir -p build
    cd build
    CC=clang CXX=clang++ cmake ../
    make -j $(nproc)
)

# build AFL
(
    cd "$FUZZER/afl"
    CC=clang CXX=clang++ make -j $(nproc)
    CC=clang CXX=clang++ make -j $(nproc) -C llvm_mode
)

# compile afl_driver.cpp
"$FUZZER/afl/afl-clang-fast++" $CXXFLAGS -std=c++11 \
    -c "$FUZZER/afl/afl_driver.cpp" -fPIC -o "$OUT/afl_driver.o"
