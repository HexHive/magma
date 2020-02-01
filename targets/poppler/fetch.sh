#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://anongit.freedesktop.org/git/poppler/poppler.git \
    --depth 1 --branch master \
    "$TARGET/repo"
git clone git://git.sv.nongnu.org/freetype/freetype2.git \
    --depth 1 --branch master \
    "$TARGET/freetype2"
