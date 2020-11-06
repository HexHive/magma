#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/google/honggfuzz.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 937ccdd9feb5114c4b32e7b03420366ff9a310ec
