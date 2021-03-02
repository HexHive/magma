#!/bin/bash

##
# Pre-requirements:
# + $1: path to captainrc (default: ./captainrc)
# + env EXTRACT: path to extraction script (default: captain/extract.sh)
##

if [ -z $1 ]; then
    set -- "./captainrc"
fi

# load the configuration file (captainrc)
set -a
source "$1"
set +a

if [ -z $WORKDIR ]; then
    echo '$WORKDIR must be specified as an environment variable.'
    exit 1
fi
MAGMA=${MAGMA:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" >/dev/null 2>&1 \
    && pwd)"}
export MAGMA
source "$MAGMA/tools/captain/common.sh"

if [ -z "$WORKER_POOL" ]; then
    WORKER_MODE=${WORKER_MODE:-1}
    WORKERS_ALL=($(lscpu -b -p | sed '/^#/d' | sort -u -t, -k ${WORKER_MODE}g | cut -d, -f1))
    WORKERS=${WORKERS:-${#WORKERS_ALL[@]}}
    export WORKER_POOL="${WORKERS_ALL[@]:0:WORKERS}"
fi

EXTRACT=${EXTRACT:-"$MAGMA"/tools/captain/extract.sh}

WORKDIR="$(realpath "$WORKDIR")"
export ARDIR="$WORKDIR/ar"
export CACHEDIR="$WORKDIR/cache"
export LOGDIR="$WORKDIR/log"
export POCDIR="$WORKDIR/poc"
export TMPDIR="$WORKDIR/tmp"
export LOCKDIR="$WORKDIR/lock"
mkdir -p "$ARDIR"
mkdir -p "$CACHEDIR"
mkdir -p "$LOGDIR"
mkdir -p "$POCDIR"
mkdir -p "$TMPDIR"
mkdir -p "$LOCKDIR"

shopt -s nullglob
rm -f "$LOCKDIR"/*
shopt -u nullglob

mutex()
{
    ##
    # Pre-requirements:
    # - $1: the mutex ID (file descriptor)
    # - $2..N: command to run
    ##
    trap 'rm -f "$LOCKDIR/$mux"' EXIT RETURN
    mux=$1
    shift
    (
      flock -xF 200 &> /dev/null
      "${@}"
    ) 200>"$LOCKDIR/$mux"
}
export -f mutex

start_extract()
{
    echo_time "Processing ${FUZZER}/${TARGET}/${PROGRAM}/${CID} on CPU $AFFINITY"

    # run the PoC extraction script
    "$EXTRACT" &> \
        "${LOGDIR}/${FUZZER}_${TARGET}_${PROGRAM}_${CID}_extract.log"

    # clean up
    rm -rf "$SHARED"

    echo_time "Finished extracting ${FUZZER}/${TARGET}/${PROGRAM}/${CID}"
}
export -f start_extract

start_ex()
{
    release_workers()
    {
        IFS=','
        read -a workers <<< "$AFFINITY"
        unset IFS
        for i in "${workers[@]}"; do
            rm -rf "$LOCKDIR/magma_cpu_$i"
        done
    }
    trap release_workers RETURN

    start_extract
}
export -f start_ex

allocate_workers()
{
    ##
    # Pre-requirements:
    # - env NUMWORKERS
    # - env WORKERSET
    ##
    cleanup()
    {
        IFS=','
        read -a workers <<< "$WORKERSET"
        unset IFS
        for i in "${workers[@]:1}"; do
            rm -rf "$LOCKDIR/magma_cpu_$i"
        done
        exit 0
    }
    trap cleanup SIGINT

    while [ $NUMWORKERS -gt 0 ]; do
        for i in $WORKER_POOL; do
            if ( set -o noclobber; > "$LOCKDIR/magma_cpu_$i" ) &>/dev/null; then
                export WORKERSET="$WORKERSET,$i"
                export NUMWORKERS=$(( NUMWORKERS - 1 ))
                allocate_workers
                return
            fi
        done
        # This times-out every 1 second to force a refresh, since a worker may
        #   have been released by the time inotify instance is set up.
        inotifywait -qq -t 1 -e delete "$LOCKDIR" &> /dev/null
    done
    cut -d',' -f2- <<< $WORKERSET
}
export -f allocate_workers

if [ -z "$ARDIR" ] || [ ! -d "$ARDIR" ]; then
    echo "Invalid archive directory!"
    exit 1
fi

cleanup()
{
    trap 'echo Cleaning up...' SIGINT
    echo_time "Waiting for jobs to finish"
    for job in `jobs -p`; do
        if ! wait $job; then
            continue
        fi
    done

    find "$LOCKDIR" -type f | while read lock; do
        if inotifywait -qq -e delete_self "$lock" &> /dev/null; then
            continue
        fi
    done

    # rm -rf "$TMPDIR"
}
trap cleanup EXIT

find "$ARDIR" -mindepth 1 -maxdepth 1 -type d | while read FUZZERDIR; do
    export FUZZER="$(basename "$FUZZERDIR")"
    find "$FUZZERDIR" -mindepth 1 -maxdepth 1 -type d | while read TARGETDIR; do
        export TARGET="$(basename "$TARGETDIR")"

        # build the Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo_time "Building $IMG_NAME"
        if ! mutex 'magma_build_cov' "$MAGMA"/tools/captain/build.sh &> \
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

                export NUMWORKERS=1
                export AFFINITY=$(allocate_workers)
                start_ex &
            done
        done
    done
done

echo_time "Post-processing script successfully terminating"