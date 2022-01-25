#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AngoraFuzzer/Angora "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 80e81c8590077bc0ac069dbd367da8ce405ff618

cp "$FUZZER/src/angora_driver.c" "$FUZZER/repo/angora_driver.c"
