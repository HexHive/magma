#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.gnome.org/GNOME/libxml2.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 681f094e5bd1d0f6b38b27701d0d1bf1ca7a9a26
