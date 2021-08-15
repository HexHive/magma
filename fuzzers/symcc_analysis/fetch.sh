#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/eurecom-s3/symcc.git "$FUZZER/symcc"
git -C "$FUZZER/symcc" submodule init
git -C "$FUZZER/symcc" submodule update

git clone --depth 1 https://github.com/Z3Prover/z3.git "$FUZZER/z3"

git clone --depth 1 -b release/11.x \
    https://github.com/llvm/llvm-project.git "$FUZZER/llvm"
