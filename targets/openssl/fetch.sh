#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/openssl/openssl.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 728d03b576f360e72bbddc7e751433575430af3b

cp "$TARGET/src/abilist.txt" "$TARGET/repo/abilist.txt"
