#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://github.com/php/php-src.git php-src \
    --depth 1 --branch master \
    "$TARGET/repo"
