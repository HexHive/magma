#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/google/AFL.git "$FUZZER/afl"
git -C "$FUZZER/afl" checkout fab1ca5ed7e3552833a18fc2116d33a9241699bc
cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/afl/afl_driver.cpp"

git clone --no-checkout https://github.com/eurecom-s3/symcc.git "$FUZZER/symcc"
git -C "$FUZZER/symcc" checkout f69364996259b76d486dd24c2f9de2968cea2089

git -C "$FUZZER/symcc" submodule init
git -C "$FUZZER/symcc" submodule update

git clone --no-checkout https://github.com/Z3Prover/z3.git "$FUZZER/z3"
git -C "$FUZZER/z3" checkout 372bb4b25afeb3d727060a7063470e4a11b78983

git clone --no-checkout https://github.com/llvm/llvm-project.git "$FUZZER/llvm"
git -C "$FUZZER/llvm" checkout ef4ffcafbb2deeb30ccc30ebcdf9a5a843a27ec1