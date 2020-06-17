#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/php/php-src.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 314eedbc35116d61e97978f5fc822dfecd14053d

git clone --no-checkout https://github.com/kkos/oniguruma.git \
    "$TARGET/repo/oniguruma"
git -C "$TARGET/repo/oniguruma" checkout ab2d300ca6fc78a50d8a87386f50cc7df6a902aa
