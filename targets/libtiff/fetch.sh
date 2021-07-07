#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.com/libtiff/libtiff.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout c145a6c14978f73bb484c955eb9f84203efcb12e

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"
