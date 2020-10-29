#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/php/php-src.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 39532f9c52ef39c629deab3a30c1e56612387396

git clone --no-checkout https://github.com/kkos/oniguruma.git \
    "$TARGET/repo/oniguruma"
git -C "$TARGET/repo/oniguruma" checkout 7c190e81397b7c37ec0e899df10be04a8eec5d4b