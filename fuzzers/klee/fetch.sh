#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/klee/klee.git "$FUZZER/klee"
git -C "$FUZZER/klee" checkout a4250b231c8527c669c0395db69bd83cf71e9065

git clone --no-checkout https://github.com/klee/klee-uclibc.git "$FUZZER/uclibc"
git -C "$FUZZER/uclibc" checkout 2a20e06561cb7f001883d06420185de0367126dd

git clone --no-checkout https://github.com/stp/stp.git "$FUZZER/stp"
git -C "$FUZZER/stp" checkout 65b8bd355d63b2cc75ec072e3ae737dd219d731d
