#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AngoraFuzzer/Angora "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 3cedcac8e65595cd2cdd950b60f654c93cf8cc2e

cp "$FUZZER/src/angora_driver.c" "$FUZZER/repo/angora_driver.c"
