#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://github.com/openssl/openssl.git \
    --depth 1 --branch master \
    "$TARGET/repo"