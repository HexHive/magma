#!/bin/bash
set -e

##
# Pre-requirements:
# + $1: path to config.yaml
# - env WORKDIR: path to directory where shared volumes will be created
# - env REPEAT: number of campaigns to run per program (per fuzzer)
# + env WORKERS: number of worker threads (default: CPU cores)
# + env TIMEOUT: time to run each campaign (default: 1m)
# + env POLL: time (in seconds) between polls (default: 5s)
# + env MAGMA_CACHE_ON_DISK: if defined, the cache workdir is mounted on disk
#       instead of in-memory (default: undefined)
# + env MAGMA_NO_ARCHIVE: if defined, campaign workdirs will not be tarballed
#       (default: undefined)
##

if [ -z $WORKDIR ] || [ -z $REPEAT ]; then
    echo '$WORKDIR and $REPEAT must be specified as environment variables.'
    exit 1
fi
if [ -z $1 ]; then
    set -- "config.yaml"
fi
MAGMA=${MAGMA:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" >/dev/null 2>&1 \
    && pwd)"}
export MAGMA
WORKERS=${WORKERS:-+0}
export POLL=${POLL:-5}
export TIMEOUT=${TIMEOUT:-1m}

WORKDIR="$(realpath "$WORKDIR")"

start_campaign()
{
    ##
    # Pre-requirements:
    # - $1: FUZZER
    # - $2: TARGET
    # - $3: PROGRAM
    # - $4: ITERATION
    # - $5: AFFINITY
    ##
    export FUZZER="$1"
    export TARGET="$2"
    export PROGRAM="$3"
    export ITERATION="$4"
    export AFFINITY="$5"
    export SHARED="$WORKDIR/cache/$FUZZER/$TARGET/$PROGRAM/$ITERATION"
    echo "Starting: $FUZZER/$TARGET/$PROGRAM/$ITERATION on CPU $AFFINITY"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    sem --id "magma_cpu_$AFFINITY" --fg -j 1 \
        "$MAGMA/tools/captain/start.sh" \
        1>/dev/null 2>&1
    AR="$WORKDIR/ar/$FUZZER/$TARGET/$PROGRAM"
    mkdir -p "$AR"
    if [ -z $MAGMA_NO_ARCHIVE ]; then
        tar -cf "${AR}/${ITERATION}.tar" "$SHARED"
    else
        mv "$SHARED" "$AR"
    fi
    rm -rf "$SHARED"
}
export -f start_campaign

get_free_cpu()
{
    ##
    # Pre-requirements:
    # - $1: WORKERS
    ##
    while true; do
        for ((i=0; i<$1; i++)); do
            if [ -d ~/.parallel/semaphores/"id-magma_cpu_$i" ] || \
               ! sem --id "magma_cpu_$i" -j 1 --st -1 1>/dev/null 2>&1; then
                continue
            fi
            # a free CPU was found, return it
            echo $i
            exit 0
        done
    done
}

# clear any stuck semaphores
rm -rf ~/.parallel/semaphores/id-magma*

# set up a RAM-backed fs for fast processing of canaries and crashes
mkdir -p "$WORKDIR/cache"
mkdir -p "$WORKDIR/ar"
if [ -z $MAGMA_CACHE_ON_DISK ]; then
    echo "Obtaining sudo permissions to mount tmpfs"
    sudo mount -t tmpfs -o size=200g,uid=$(id -u $USER),gid=$(id -g $USER) \
        tmpfs "$WORKDIR/cache"
fi

echo "$(yq r --printMode p "$1" '*')" | \
while read FUZZER; do
    export FUZZER
    echo "$(yq r "$1" $FUZZER.'**')" | \
    while read TARGET; do
        export TARGET
        # build the magma/fuzzer/target Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo "Building $IMG_NAME"
        $MAGMA/tools/captain/build.sh 1>/dev/null 2>&1

        # start the multiple fuzzer campaigns
        yq read "$MAGMA/targets/$TARGET/config.yaml" programs | \
        while read PROGRAM; do
            PROGRAM="$(echo "$PROGRAM" | cut -c 3-)"
            for ((i=0; i<$REPEAT; i++)); do
                AFFINITY=$(get_free_cpu $WORKERS)
                sem --id "magma" -u -j $WORKERS \
                    start_campaign "$FUZZER" "$TARGET" "$PROGRAM" $i $AFFINITY
                sleep 1 # this prevents races over the CPU (hacky)
            done
        done
    done
done

sem --id "magma" --wait

if [ -z $MAGMA_CACHE_ON_DISK ]; then
    echo "Obtaining sudo permissions to umount tmpfs"
    sudo umount "$WORKDIR/cache"
fi