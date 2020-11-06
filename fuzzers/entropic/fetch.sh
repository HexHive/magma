#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/llvm/llvm-project.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 3d120b6f7be816d188bd05271fff17f0030db9b2