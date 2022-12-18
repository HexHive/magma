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

# Build LLVM 6
mkdir -p "$FUZZER/llvm-build" "$FUZZER/llvm-install"
cd "$FUZZER/llvm-build"

cmake \
    -GNinja \
    -DLLVM_ENABLE_ASSERTIONS=On \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=../llvm-install \
    ../llvm6
ninja
ninja install

rm -rf "$FUZZER/llvm-build"

# Build TortoiseFuzz
cd "$FUZZER/repo"

export PATH="$FUZZER/llvm-install/bin:$PATH"
export LD_LIBRARY_PATH="$FUZZER/llvm-install/lib:$LD_LIBRARY_PATH"
export CC=clang
export CXX=clang++

make -j$(nproc)

$CXX -std=c++11 -O2 -c -o "$OUT/afl_driver.o" "$FUZZER/repo/afl_driver.cpp"
