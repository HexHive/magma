#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/libsndfile/libsndfile.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout d60deb5d8691997b6bb28d88e3b43f322073d146