#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

# TODO filter patches by target config.yaml
find "$TARGET/patches/setup" "$TARGET/patches/bugs" -name "*.patch" | \
while read patch; do
    echo "Applying $patch"
    patch -p1 -d "$TARGET/repo" <"$patch"
done
