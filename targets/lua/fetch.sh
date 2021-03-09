#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://github.com/lua/lua.git \
    --depth 1 --branch master \
    "$TARGET/repo"
