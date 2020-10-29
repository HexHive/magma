#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.com/libtiff/libtiff.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 2e822691d750c01cec5b5cc4ee73567a204ab2a3

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"
