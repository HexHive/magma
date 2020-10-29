#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.freedesktop.org/poppler/poppler.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 2706eca3ad3af99fa6551b9d6fcdc69eb0a0aa4e

git clone --no-checkout git://git.sv.nongnu.org/freetype/freetype2.git \
    "$TARGET/freetype2"
git -C "$TARGET/freetype2" checkout 804e625def2cfb64ef2f4c8877cd3fa11e86e208