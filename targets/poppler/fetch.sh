#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.freedesktop.org/poppler/poppler.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 1d23101ccebe14261c6afc024ea14f29d209e760

git clone --no-checkout git://git.sv.nongnu.org/freetype/freetype2.git \
    "$TARGET/freetype2"
git -C "$TARGET/freetype2" checkout 50d0033f7ee600c5f5831b28877353769d1f7d48