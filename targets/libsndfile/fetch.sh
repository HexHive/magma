#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --depth 1 https://github.com/libsndfile/libsndfile.git \
    "$TARGET/repo"