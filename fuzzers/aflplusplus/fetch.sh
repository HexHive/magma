#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone https://github.com/AFLplusplus/AFLplusplus "$FUZZER/repo"
cd "$FUZZER/repo" || exit 1
git checkout dev
