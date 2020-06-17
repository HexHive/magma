#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://anongit.freedesktop.org/git/poppler/poppler.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout bf15ccd4861d10e2338d0b1b2a65f222eb4e9893

git clone --no-checkout git://git.sv.nongnu.org/freetype/freetype2.git \
    "$TARGET/freetype2"
git -C "$TARGET/freetype2" checkout 7438235b42e9d425888c68519d1e05dd2b69fff7
