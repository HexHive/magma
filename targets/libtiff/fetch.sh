#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://gitlab.com/libtiff/libtiff \
    --depth 1 --branch master \
    "$TARGET/repo"
git clone https://github.com/madler/zlib \
    --depth 1 --branch master \
    "$TARGET/zlib"
git clone https://github.com/libjpeg-turbo/libjpeg-turbo \
    --depth 1 --branch master \
    "$TARGET/libjpeg-turbo"
git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit \
    "$TARGET/jbigkit"

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"