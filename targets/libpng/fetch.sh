#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/glennrp/libpng.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout dbe3e0c43e549a1602286144d94b0666549b18e6
