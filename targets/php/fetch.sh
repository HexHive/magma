#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/php/php-src.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout bc39abe8c3c492e29bc5d60ca58442040bbf063b

git clone --no-checkout https://github.com/kkos/oniguruma.git \
    "$TARGET/repo/oniguruma"
git -C "$TARGET/repo/oniguruma" checkout 227ec0bd690207812793c09ad70024707c405376