#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/eurecom-s3/symcc.git "$FUZZER/symcc"
git -C "$FUZZER/symcc" checkout 82151a62e3b702a2c699ca4d8ef91d3bf9beeb2b

git -C "$FUZZER/symcc" submodule init
git -C "$FUZZER/symcc" submodule update

git clone --no-checkout https://github.com/Z3Prover/z3.git "$FUZZER/z3"
git -C "$FUZZER/z3" checkout 897cbf347bcf73ac986d50636b15f09968130880

git clone --no-checkout https://github.com/llvm/llvm-project.git "$FUZZER/llvm"
git -C "$FUZZER/llvm" checkout 29cc50e17a6800ca75cd23ed85ae1ddf3e3dcc14