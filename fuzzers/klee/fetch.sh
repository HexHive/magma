#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/klee/klee.git "$FUZZER/klee"
git -C "$FUZZER/klee" checkout df04aeadefb4e1c34c7ef8b9123947ff045a34d9

git clone --no-checkout https://github.com/klee/klee-uclibc.git "$FUZZER/uclibc"
git -C "$FUZZER/uclibc" checkout 9351bdc9ad61ba25b051bef36f78b709ba50ff28

git clone --no-checkout https://github.com/stp/stp.git "$FUZZER/stp"
git -C "$FUZZER/stp" checkout 876589d45f656f13cefeb04a2f13005d0fa0c932
