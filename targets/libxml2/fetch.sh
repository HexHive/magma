#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://gitlab.gnome.org/GNOME/libxml2.git \
    --branch master \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 0c1b4fd2cfc020451110d8131e8007203e2ccffc