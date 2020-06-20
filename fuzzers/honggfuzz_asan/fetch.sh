#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/google/honggfuzz.git \
    "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 5fa5d0a1aecdb422091a3eb723e2aae80c122209
