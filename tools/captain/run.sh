#!/bin/bash -e

##
# Pre-requirements:
# + $1: path to captainrc (default: ./captainrc)
##

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

if [ -z "$WORKER_POOL" ]; then
    WORKER_MODE=${WORKER_MODE:-1}
    WORKERS_ALL=($(lscpu -b -p | sed '/^#/d' | sort -u -t, -k ${WORKER_MODE}g | cut -d, -f1))
    WORKERS=${WORKERS:-${#WORKERS_ALL[@]}}
    export WORKER_POOL="${WORKERS_ALL[@]:0:WORKERS}"
fi
export CAMPAIGN_WORKERS=${CAMPAIGN_WORKERS:-1}

TMPFS_SIZE=${TMPFS_SIZE:-50g}
export POLL=${POLL:-5}
export TIMEOUT=${TIMEOUT:-1m}

WORKDIR="$(realpath "$WORKDIR")"
export ARDIR="$WORKDIR/ar"
export CACHEDIR="$WORKDIR/cache"
export LOGDIR="$WORKDIR/log"
export POCDIR="$WORKDIR/poc"
export LOCKDIR="$WORKDIR/lock"
mkdir -p "$ARDIR"
mkdir -p "$CACHEDIR"
mkdir -p "$LOGDIR"
mkdir -p "$POCDIR"
mkdir -p "$LOCKDIR"

shopt -s nullglob
rm -f "$LOCKDIR"/*
shopt -u nullglob

export MUX_TAR=magma_tar
export MUX_CID=magma_cid

get_next_cid()
{
    ##
    # Pre-requirements:
    # - $1: the directory where campaigns are stored
    ##
    shopt -s nullglob
    campaigns=("$1"/*)
    if [ ${#campaigns[@]} -eq 0 ]; then
        echo 0
        dir="$1/0"
    else
        cids=($(sort -n < <(basename -a "${campaigns[@]}")))
        for ((i=0;;i++)); do
            if [ -z ${cids[i]} ] || [ ${cids[i]} -ne $i ]; then
                echo $i
                dir="$1/$i"
                break
            fi
        done
    fi
    # ensure the directory is created to prevent races
    mkdir -p "$dir"
    while [ ! -d "$dir" ]; do sleep 1; done
}
export -f get_next_cid

mutex()
{
    ##
    # Pre-requirements:
    # - $1: the mutex ID (file descriptor)
    # - $2..N: command to run
    ##
    trap 'rm -f "$LOCKDIR/$mux"' EXIT
    mux=$1
    shift
    (
      flock -xF 200 &> /dev/null
      "${@}"
    ) 200>"$LOCKDIR/$mux"
}
export -f mutex

start_campaign()
{
    launch_campaign()
    {
        export SHARED="$CAMPAIGN_CACHEDIR/$CACHECID"
        mkdir -p "$SHARED" && chmod 777 "$SHARED"

        echo_time "Container $FUZZER/$TARGET/$PROGRAM/$ARCID started on CPU $AFFINITY"
        "$MAGMA"/tools/captain/start.sh &> \
            "${LOGDIR}/${FUZZER}_${TARGET}_${PROGRAM}_${ARCID}_container.log"
        echo_time "Container $FUZZER/$TARGET/$PROGRAM/$ARCID stopped"

        if [ ! -z $POC_EXTRACT ]; then
            "$MAGMA"/tools/captain/extract.sh
        fi

        if [ -z $NO_ARCHIVE ]; then
            # only one tar job runs at a time, to prevent out-of-storage errors
            mutex $MUX_TAR \
              tar -cf "${CAMPAIGN_ARDIR}/${ARCID}/${TARBALL_BASENAME}.tar" -C "$SHARED" . &>/dev/null && \
            rm -rf "$SHARED"
        else
            # overwrites empty $ARCID directory with the $SHARED directory
            mv -T "$SHARED" "${CAMPAIGN_ARDIR}/${ARCID}"
        fi
    }
    export -f launch_campaign

    while : ; do
        export CAMPAIGN_CACHEDIR="$CACHEDIR/$FUZZER/$TARGET/$PROGRAM"
        export CACHECID=$(mutex $MUX_CID \
                get_next_cid "$CAMPAIGN_CACHEDIR")
        export CAMPAIGN_ARDIR="$ARDIR/$FUZZER/$TARGET/$PROGRAM"
        export ARCID=$(mutex $MUX_CID \
                get_next_cid "$CAMPAIGN_ARDIR")

        errno_lock=69
        SHELL=/bin/bash flock -xnF -E $errno_lock "${CAMPAIGN_CACHEDIR}/${CACHECID}" \
            flock -xnF -E $errno_lock "${CAMPAIGN_ARDIR}/${ARCID}" \
                -c launch_campaign || \
        if [ $? -eq $errno_lock ]; then
            continue
        fi
        break
    done
}
export -f start_campaign

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
    trap release_workers EXIT

    start_campaign
    exit 0
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

# set up a RAM-backed fs for fast processing of canaries and crashes
if [ -z $CACHE_ON_DISK ]; then
    echo_time "Obtaining sudo permissions to mount tmpfs"
    if mountpoint -q -- "$CACHEDIR"; then
        sudo umount -f "$CACHEDIR"
    fi
    sudo mount -t tmpfs -o size=$TMPFS_SIZE,uid=$(id -u $USER),gid=$(id -g $USER) \
        tmpfs "$CACHEDIR"
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

    if [ -z $CACHE_ON_DISK ]; then
        echo_time "Obtaining sudo permissions to umount tmpfs"
        sudo umount "$CACHEDIR"
    fi
}

trap cleanup EXIT

# schedule campaigns
for FUZZER in "${FUZZERS[@]}"; do
    export FUZZER

    TARGETS=($(get_var_or_default $FUZZER 'TARGETS'))
    for TARGET in "${TARGETS[@]}"; do
        export TARGET

        export FUZZARGS="$(get_var_or_default $FUZZER $TARGET 'FUZZARGS')"

        # build the Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo_time "Building $IMG_NAME"
        if ! "$MAGMA"/tools/captain/build.sh &> \
            "${LOGDIR}/${FUZZER}_${TARGET}_build.log"; then
            echo_time "Failed to build $IMG_NAME. Check build log for info."
            continue
        fi

        PROGRAMS=($(get_var_or_default $FUZZER $TARGET 'PROGRAMS'))
        for PROGRAM in "${PROGRAMS[@]}"; do
            export PROGRAM
            export ARGS="$(get_var_or_default $FUZZER $TARGET $PROGRAM 'ARGS')"

            echo_time "Starting campaigns for $PROGRAM $ARGS"
            for ((i=0; i<$REPEAT; i++)); do
                export NUMWORKERS="$(get_var_or_default $FUZZER 'CAMPAIGN_WORKERS')"
                export AFFINITY=$(allocate_workers)
                start_ex &
            done
        done
    done
done
