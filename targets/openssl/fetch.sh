#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/openssl/openssl.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 24b6261e5bb286fa494e7208a3de28365e0ca004
