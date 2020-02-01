#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://github.com/glennrp/libpng.git \
    --depth 1 --branch libpng16 \
    "$TARGET/repo"