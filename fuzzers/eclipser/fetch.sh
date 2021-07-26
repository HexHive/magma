#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/SoftSec-KAIST/Eclipser.git "$FUZZER/eclipser"
cp "$FUZZER/src/standalone_driver.cpp" "$FUZZER/eclipser/standalone_driver.cpp"

git clone --depth 1 https://github.com/google/AFL.git "$FUZZER/afl"
cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/afl/afl_driver.cpp"
