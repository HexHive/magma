#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/csienslab/instrim.git \
    "$FUZZER/instrim"
git -C "$FUZZER/instrim" checkout 82b56358f5f842a194e458c63c26799f0ac393d7

# Fix: CMake linker flags
cat >> "$FUZZER/instrim/CMakeLists.txt" << EOF
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,nodelete")
EOF

git clone --no-checkout https://github.com/google/AFL.git "$FUZZER//afl"
git -C "$FUZZER/afl" checkout fab1ca5ed7e3552833a18fc2116d33a9241699bc
patch -d "$FUZZER/afl" -p1 < "$FUZZER/instrim/afl-fuzzer.patch"

cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/afl/afl_driver.cpp"
