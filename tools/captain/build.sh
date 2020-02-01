#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# + env MAGMA: path to magma root (default: ../../)
# + env FORCE: if set, force build even if image exists (default: 0)
##

if [ -z $FUZZER ] || [ -z $TARGET ]; then
    echo '$FUZZER and $TARGET must be specified as environment variables.'
    exit 1
fi
IMG_NAME="magma/$FUZZER/$TARGET"
MAGMA=${MAGMA:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" >/dev/null 2>&1 \
    && pwd)"}

if [ -z $(docker image ls -q "$IMG_NAME") ] || [ ! -z $FORCE ]; then
    docker build -t "$IMG_NAME" \
        --build-arg fuzzer_name="$FUZZER" \
        --build-arg target_name="$TARGET" \
        -f "$MAGMA/docker/Dockerfile" "$MAGMA"
fi

echo "$IMG_NAME"