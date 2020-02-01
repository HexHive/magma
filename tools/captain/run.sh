#!/bin/bash
set -e

##
# Pre-requirements:
# - env WORKDIR: path to directory where shared volumes will be created
# - env REPEAT: number of campaigns to run per program (per fuzzer)
# + env WORKERS: number of worker threads (default: CPU cores)
# + env TIMEOUT: time to run each campaign (default: 1m)
# + env POLL: time (in seconds) between polls (default: 5s)
##

if [ -z $WORKDIR ] || [ -z $REPEAT ]; then
    echo '$WORKDIR and $REPEAT must be specified as environment variables.'
    exit 1
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
    export SHARED="$WORKDIR/$FUZZER/$TARGET/$PROGRAM/$ITERATION"
    echo "Starting: $FUZZER/$TARGET/$PROGRAM/$ITERATION on CPU $AFFINITY"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    sem --id "magma_cpu_$AFFINITY" -j 1 \
        tools/captain/start.sh \
        1>/dev/null 2>&1
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
            if ! sem --id "magma_cpu_$i" -j 1 \
                    1>/dev/null 2>&1; then
                continue
            fi
            # a free CPU was found, return it
            echo $i
            exit 0
        done
    done
}

cd "$MAGMA"
for FUZZER in fuzzers/*; do
    export FUZZER="${FUZZER##*/}"
    for TARGET in targets/*; do
    # for TARGET in openssl; do
        export TARGET="${TARGET##*/}"
        # build the magma/fuzzer/target Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo "Building $IMG_NAME"
        tools/captain/build.sh 1>/dev/null 2>&1

        # start the multiple fuzzer campaigns
        yq read "targets/$TARGET/config.yaml" programs | \
        while read PROGRAM; do
            PROGRAM="$(echo "$PROGRAM" | cut -c 3-)"
            for ((i=0; i<$REPEAT; i++)); do
                AFFINITY=$(get_free_cpu $WORKERS)
                sem --id "magma" -u -j $WORKERS \
                    start_campaign "$FUZZER" "$TARGET" "$PROGRAM" $i $AFFINITY
            done
        done
    done
done

sem --id "magma" --wait