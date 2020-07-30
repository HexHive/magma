#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AFLplusplus/AFLplusplus.git \
    "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 4a51cb71fb8785325dedac693cdea4648f6e5279
