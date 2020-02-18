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
    # - $1: FUZZER
    # - $2: TARGET
    # - $3: PROGRAM
    # - $4: ARGS
    # - $5: ITERATION
    # - $6: AFFINITY
    ##
    export ITERATION="$1"
    export AFFINITY="$2"
    export FUZZER="$3"
    export TARGET="$4"
    export PROGRAM="$5"
    export ARGS="${@:6}"
    export SHARED="$WORKDIR/cache/$FUZZER/$TARGET/$PROGRAM/$ITERATION"

    echo "Starting: $FUZZER/$TARGET/$PROGRAM/$ITERATION on CPU $AFFINITY"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    sem --id "magma_cpu_$AFFINITY" --fg -j 1 \
        "$MAGMA/tools/captain/start.sh" \
        1>/dev/null 2>&1
    AR="$WORKDIR/ar/$FUZZER/$TARGET/$PROGRAM"
    mkdir -p "$AR"
    if [ -z $MAGMA_NO_ARCHIVE ]; then
        sem --id "magma_tar" --fg -j 1 \
          tar -cf "${AR}/${ITERATION}.tar" -C "$SHARED" . 1>/dev/null 2>&1 && \
        rm -rf "$SHARED"
    else
        mv "$SHARED" "$AR"
    fi
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
        sleep 1 # yet another hacky fix...
    done
}

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

        # build the magma/fuzzer/target Docker image
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
            echo "Starting campaign for: $PROGRAM $ARGS"

            for ((i=0; i<$REPEAT; i++)); do
                AFFINITY=$(get_free_cpu $WORKERS)
                sem --id "magma" -u -j $WORKERS \
                    start_campaign $i $AFFINITY "$FUZZER" "$TARGET" "$PROGRAM" "$ARGS"
                sleep 1 # this reduces races over the CPU (hacky)
            done
        done
        unset customprgs
    done
done

sem --id "magma" --wait

if [ -z $MAGMA_CACHE_ON_DISK ]; then
    echo "Obtaining sudo permissions to umount tmpfs"
    sudo umount "$WORKDIR/cache"
fi
