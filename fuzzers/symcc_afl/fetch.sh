#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/google/AFL.git "$FUZZER/afl"
git -C "$FUZZER/afl" checkout 82b5e359463238d790cadbe2dd494d6a4928bff3
cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/afl/afl_driver.cpp"

git clone --no-checkout https://github.com/eurecom-s3/symcc.git "$FUZZER/symcc"
git -C "$FUZZER/symcc" checkout 1cc757dfbc9ac7e26ddcadd48d38c30c2c540116
git -C "$FUZZER/symcc" submodule init
git -C "$FUZZER/symcc" submodule update

git clone --no-checkout https://github.com/Z3Prover/z3.git "$FUZZER/z3"
git -C "$FUZZER/z3" checkout 78b88f761ca21f0287eb6563092b706d15c7b71b

git clone --depth 1 -b release/11.x \
    https://github.com/llvm/llvm-project.git "$FUZZER/llvm"