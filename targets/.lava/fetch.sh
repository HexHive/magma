#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

curl 'https://panda.moyix.net/~moyix/lava_corpus.tar.xz' -o "$OUT/lava_corpus.tar.xz" && \
mkdir -p "$TARGET/repo" && \
tar -C "$TARGET/repo" --strip-components=1 -xJf "$OUT/lava_corpus.tar.xz"