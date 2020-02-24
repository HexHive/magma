#!/bin/bash -e

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
# + env TMPFS_SIZE: the size of the tmpfs mounted volume (default: 50g)
# + env MAGMA: path to magma root (default: ../../)
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
WORKERS=${WORKERS:-(( $(nproc) - 2 ))}
TMPFS_SIZE=${TMPFS_SIZE:-50g}
export POLL=${POLL:-5}
export TIMEOUT=${TIMEOUT:-1m}

WORKDIR="$(realpath "$WORKDIR")"

start_campaign()
{
    ##
    # Pre-requirements:
    # - env AFFINITY
    # - $1: ITERATION
    # - $2: FUZZER
    # - $3: TARGET
    # - $4: PROGRAM
    # - $5+: ARGS
    ##
    export ITERATION="$1"
    export FUZZER="$2"
    export TARGET="$3"
    export PROGRAM="$4"
    # The following line results in joining the original ARGS by spaces, which
    # breaks single-words-with-spaces into multiple words, which is not ideal.
    # Consider using arrays instead. Bash currently does not support exporting
    # arrays, however.
    # Future fix: export ARGS=("${@:5}")
    export ARGS="${@:5}"
    export SHARED="$WORKDIR/cache/$FUZZER/$TARGET/$PROGRAM/$ITERATION"

    echo "Started $FUZZER/$TARGET/$PROGRAM/$ITERATION on CPU $AFFINITY"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    "$MAGMA/tools/captain/start.sh" 1>/dev/null 2>&1

    AR="$WORKDIR/ar/$FUZZER/$TARGET/$PROGRAM"
    mkdir -p "$AR"
    if [ -z $MAGMA_NO_ARCHIVE ]; then
        # only one tar job runs at a time, to prevent out-of-space errors
        sem --id "magma_tar" --fg -j 1 \
          tar -cf "${AR}/${ITERATION}.tar" -C "$SHARED" . 1>/dev/null 2>&1 && \
        rm -rf "$SHARED"
    else
        mv "$SHARED" "$AR"
    fi
}
export -f start_campaign

start_ex()
{
    ##
    # Pre-requirements:
    # - $1: WORKERS
    # - $2: NUMCPUS
    # - $3: CPUSET
    # - $4+: COMMAND
    ##
    WORKERS=$1
    NUMCPUS=$2
    CPUSET=$3
    COMMAND=("${@:4}")
    if [ $NUMCPUS -gt 0 ]; then
        while true; do
            for ((i=0; i<$WORKERS; i++)); do
                if [ -d ~/.parallel/semaphores/"id-magma_cpu_$i" ] || \
                        ! sem -u --id "magma_cpu_$i" -j 1 --st -1 --fg \
                        start_ex $WORKERS $((NUMCPUS - 1)) "$CPUSET,$i" \
                        ${COMMAND[@]}; then
                    continue
                else
                    exit 0
                fi
            done
            sleep 1 # yet another hacky fix...
        done
    else
        # release transaction lock (hacky :/)
        rm -r ~/.parallel/semaphores/id-magma
        # GNU Parallel does not re-aquire the mutex when it steals it, thus the
        # following statement does not do the intended task of releasing the
        # mutex after stealing it:
        # sem --id "magma" --st 1
        # Hence, we have to delete the metadata used by GNU Parallel, as above

        export AFFINITY=$(cut -d',' -f2- <<< $CPUSET)
        ${COMMAND[@]}
    fi
}
export -f start_ex

contains_element () {
    local e match="$1"
    shift
    for e; do [[ "$e" == "$match" ]] && return 0; done
    return 1
}

# clear any stuck semaphores
rm -rf ~/.parallel/semaphores/id-magma*

# set up a RAM-backed fs for fast processing of canaries and crashes
mkdir -p "$WORKDIR/cache"
mkdir -p "$WORKDIR/ar"
if [ -z $MAGMA_CACHE_ON_DISK ]; then
    echo "Obtaining sudo permissions to mount tmpfs"
    if mountpoint -q -- "$WORKDIR/cache"; then
        sudo umount -f "$WORKDIR/cache"
    fi
    sudo mount -t tmpfs -o size=$TMPFS_SIZE,uid=$(id -u $USER),gid=$(id -g $USER) \
        tmpfs "$WORKDIR/cache"
fi

mapfile -t fuzzers < <(yq r --printMode p "$1" '*')
for FUZZER in "${fuzzers[@]}"; do
    export FUZZER

    mapfile -t items < <(yq r --printMode p "$1" $FUZZER'[*]')
    for item in "${items[@]}"; do
        TARGET="$(yq r --printMode p "$1" "$item"'.*' | tr -d '[]')"
        if [ -z "$TARGET" ]; then
            TARGET="$(yq r "$1" "$item")"
        else
            mapfile -t customprgs < <(yq r "$1" "$item"'.**')
            item="$(tr -d '[]' <<< "$item")"
            TARGET="${TARGET/$item'.'/}"
        fi
        export TARGET

        # build the Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo "Building $IMG_NAME"
        $MAGMA/tools/captain/build.sh 1>/dev/null 2>&1

        mapfile -t defaultprgs < <(yq r "$MAGMA/targets/$TARGET/config.yaml" \
            'programs[*]')
        for prog in "${defaultprgs[@]}"; do
            PROGRAM="$(eval echo $(awk -F': ' '{print $1}' <<< "$prog"))"
            ARGS="$(eval echo $(awk -F': ' '{print $2}' <<< "$prog"))"
            if [ ${#customprgs[@]} -ne 0 ] && \
                    ! contains_element "$PROGRAM" "${customprgs[@]}"; then
                continue
            fi

            echo "Starting campaigns for $PROGRAM $ARGS"
            for ((i=0; i<$REPEAT; i++)); do
                NUMCPUS=1 # this can later be read from fuzzer config
                # acquire transaction lock
                sem --id "magma" -u \
                    start_ex $WORKERS $NUMCPUS "-1" \
                    start_campaign $i "$FUZZER" "$TARGET" "$PROGRAM" "$ARGS"
            done
        done
        unset customprgs
    done
done

for ((i=0; i<$WORKERS; i++)); do
    sem --id "magma_cpu_$i" --wait
done

if [ -z $MAGMA_CACHE_ON_DISK ]; then
    echo "Obtaining sudo permissions to umount tmpfs"
    sudo umount "$WORKDIR/cache"
fi
