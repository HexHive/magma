#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/puppet-meteor/MOpt-AFL.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 45b9f38d2d8b699fd571cfde1bf974974339a21e
mv "$FUZZER/repo/MOpt"/* "$FUZZER/repo"
#wget -O "$FUZZER/repo/afl_driver.cpp" \
#    "https://cs.chromium.org/codesearch/f/chromium/src/third_party/libFuzzer/src/afl/afl_driver.cpp"
cp "$FUZZER/src/afl_driver.cpp" "$FUZZER/repo/afl_driver.cpp"
