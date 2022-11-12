#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

export PATH="/usr/local/go/bin:$PATH"
export GOPATH="$FUZZER/repo/go"

mkdir -p $GOPATH
go install github.com/SRI-CSL/gllvm/cmd/...@latest

git clone --no-checkout https://github.com/Dongdongshe/K-Scheduler "$FUZZER/repo/kscheduler"
git -C "$FUZZER/repo/kscheduler" checkout 36bc5aa658fa7c9716aee08a8ff22419f28e3fe9

sed -i '{s/^int main/__attribute__((weak)) &/}' \
    "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' \
    "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"
