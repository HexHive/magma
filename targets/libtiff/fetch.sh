#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.com/libtiff/libtiff \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 1373f8dacb47d0e256889172c6a5a6dc606f00ba

git clone --no-checkout https://github.com/madler/zlib \
    "$TARGET/zlib"
git -C "$TARGET/zlib" checkout cacf7f1d4e3d44d871b605da3b647f07d718623f

git clone --no-checkout https://github.com/libjpeg-turbo/libjpeg-turbo \
    "$TARGET/libjpeg-turbo"
git -C "$TARGET/libjpeg-turbo" checkout b443c541b9a6fdcac214f9f003de0aa13e480ac1

git clone --no-checkout https://www.cl.cam.ac.uk/~mgk25/git/jbigkit \
    "$TARGET/jbigkit"
git -C "$TARGET/jbigkit" checkout dce101373d87445ed55a385fddad02d8a8751de4

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"