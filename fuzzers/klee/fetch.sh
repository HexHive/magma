#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/klee/klee.git "$FUZZER/klee"
git clone --depth 1 https://github.com/klee/klee-uclibc.git "$FUZZER/uclibc"
git clone --depth 1 https://github.com/stp/stp.git "$FUZZER/stp"
