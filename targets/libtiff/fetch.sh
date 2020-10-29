#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://gitlab.com/libtiff/libtiff \
    --depth 1 --branch master \
    "$TARGET/repo"

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"
