#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/google/honggfuzz.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout fc6b818c1276056bc565d07edec6ada784cd1670
