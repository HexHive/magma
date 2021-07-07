#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/glennrp/libpng.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout a37d4836519517bdce6cb9d956092321eca3e73b