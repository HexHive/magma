#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://github.com/php/php-src.git \
    --depth 1 --branch master \
    "$TARGET/repo"

git clone https://github.com/kkos/oniguruma.git "$TARGET/repo/oniguruma"