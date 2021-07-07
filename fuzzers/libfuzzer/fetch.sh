#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/llvm/llvm-project.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 29cc50e17a6800ca75cd23ed85ae1ddf3e3dcc14