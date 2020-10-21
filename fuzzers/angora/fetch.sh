#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/AngoraFuzzer/Angora "$FUZZER/repo"

cp "$FUZZER/src/angora_driver.c" "$FUZZER/repo/angora_driver.c"
