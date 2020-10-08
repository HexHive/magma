#!/bin/bash

##
# Pre-requirements:
# + $1: path to captainrc (default: ./captainrc)
# + env EXTRACT: path to extraction script (default: captain/extract.sh)
##

cleanup() {
    rm -rf "$TMPDIR"
}

trap cleanup EXIT

if [ -z $1 ]; then
    set -- "./captainrc"
fi

# load the configuration file (captainrc)
set -a
source "$1"
set +a

if [ -z $WORKDIR ] || [ -z $REPEAT ]; then
    echo '$WORKDIR and $REPEAT must be specified as environment variables.'
    exit 1
fi
MAGMA=${MAGMA:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" >/dev/null 2>&1 \
    && pwd)"}
export MAGMA
source "$MAGMA/tools/captain/common.sh"

EXTRACT=${EXTRACT:-"$MAGMA"/tools/captain/extract.sh}

WORKDIR="$(realpath "$WORKDIR")"
export ARDIR="$WORKDIR/ar"
export CACHEDIR="$WORKDIR/cache"
export LOGDIR="$WORKDIR/log"
export POCDIR="$WORKDIR/poc"
export TMPDIR="$WORKDIR/tmp"
mkdir -p "$ARDIR"
mkdir -p "$CACHEDIR"
mkdir -p "$LOGDIR"
mkdir -p "$POCDIR"
mkdir -p "$TMPDIR"

if [ -z "$ARDIR" ] || [ ! -d "$ARDIR" ]; then
    echo "Invalid archive directory!"
    exit 1
fi

find "$ARDIR" -mindepth 1 -maxdepth 1 -type d | while read FUZZERDIR; do
    export FUZZER="$(basename "$FUZZERDIR")"
    find "$FUZZERDIR" -mindepth 1 -maxdepth 1 -type d | while read TARGETDIR; do
        export TARGET="$(basename "$TARGETDIR")"

        # build the Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo_time "Building $IMG_NAME"
        if ! "$MAGMA"/tools/captain/build.sh &> \
            "${LOGDIR}/${FUZZER}_${TARGET}_build.log"; then
            echo_time "Failed to build $IMG_NAME. Check build log for info."
            continue
        fi

        find "$TARGETDIR" -mindepth 1 -maxdepth 1 -type d | while read PROGRAMDIR; do
            export PROGRAM="$(basename "$PROGRAMDIR")"
            export ARGS="$(get_var_or_default $FUZZER $TARGET $PROGRAM 'ARGS')"
            find "$PROGRAMDIR" -mindepth 1 -maxdepth 1 -type d | while read CAMPAIGNDIR; do
                export CID="$(basename "$CAMPAIGNDIR")"
                export SHARED="$TMPDIR/$FUZZER/$TARGET/$PROGRAM/$CID"

                # select whether to copy or untar
                if [ -f "$CAMPAIGNDIR/${TARBALL_BASENAME}.tar" ]; then
                    mkdir -p "$SHARED"
                    tar -C "$SHARED" -xf "$CAMPAIGNDIR/${TARBALL_BASENAME}.tar"
                else
                    cp -r "$CAMPAIGNDIR" "$SHARED"
                fi

                # run the PoC extraction script
                "$EXTRACT"

                # clean up
                rm -rf "$SHARED"
            done
        done
    done
done
