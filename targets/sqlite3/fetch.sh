#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

REF=4adc0a1b0d84c2df

curl "https://www.sqlite.org/src/tarball/sqlite.tar.gz?r=$REF" \
    -o "$OUT/sqlite.tar.gz" && \
mkdir -p "$TARGET/repo" && \
tar -C "$TARGET/repo" --strip-components=1 -xzf "$OUT/sqlite.tar.gz"