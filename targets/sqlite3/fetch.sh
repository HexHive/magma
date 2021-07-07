#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

curl "https://www.sqlite.org/src/tarball/sqlite.tar.gz?r=8c432642572c8c4b" \
  -o "$OUT/sqlite.tar.gz" && \
mkdir -p "$TARGET/repo" && \
tar -C "$TARGET/repo" --strip-components=1 -xzf "$OUT/sqlite.tar.gz"