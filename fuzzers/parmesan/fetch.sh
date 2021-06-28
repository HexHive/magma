#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/vusec/parmesan "$FUZZER/repo"

# Use Angora version of gen_library_abilist.sh script (because it handles
# numbered .so extensions properly)
wget -O "$FUZZER/repo/tools/gen_library_abilist.sh" \
    https://raw.githubusercontent.com/AngoraFuzzer/Angora/master/tools/gen_library_abilist.sh

cp "$FUZZER/src/angora_driver.c" "$FUZZER/repo/angora_driver.c"
