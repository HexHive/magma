#!/bin/bash -e

##
# Pre-requirements:
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# - env PROGRAM: program name (name of binary artifact from $TARGET/build.sh)
# - env ARGS: program launch arguments
# - env FUZZARGS: fuzzer arguments
# - env POLL: time (in seconds) between polls
# - env TIMEOUT: time to run the campaign
# + env SHARED: path to host-local volume where fuzzer findings are saved
#       (default: no shared volume)
# + env AFFINITY: the CPU to bind the container to (default: no affinity)
# + env ENTRYPOINT: a custom entry point to launch in the container (default:
#       $MAGMA/run.sh)
##

cleanup() {
    if [ ! -t 1 ]; then
        docker rm -f $container_id &> /dev/null
    fi
    exit 0
}

trap cleanup EXIT SIGINT SIGTERM

if [ -z $FUZZER ] || [ -z $TARGET ] || [ -z $PROGRAM ]; then
    echo '$FUZZER, $TARGET, and $PROGRAM must be specified as' \
         'environment variables.'
    exit 1
fi

MAGMA=${MAGMA:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" >/dev/null 2>&1 \
    && pwd)"}
export MAGMA
source "$MAGMA/tools/captain/common.sh"

IMG_NAME="magma/$FUZZER/$TARGET"

if [ ! -z $AFFINITY ]; then
    flag_aff="--cpuset-cpus=$AFFINITY --env=AFFINITY=$AFFINITY"
fi

if [ ! -z "$ENTRYPOINT" ]; then
    flag_ep="--entrypoint=$ENTRYPOINT"
fi

if [ ! -z "$SHARED" ]; then
    SHARED="$(realpath "$SHARED")"
    flag_volume="--volume=$SHARED:/magma_shared"
fi

if [ -t 1 ]; then
    docker run -it $flag_volume \
        --cap-add=SYS_PTRACE --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
        --env=FUZZARGS="$FUZZARGS" --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" \
        $flag_aff $flag_ep "$IMG_NAME"
else
    container_id=$(
    docker run -dt $flag_volume \
        --cap-add=SYS_PTRACE --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
        --env=FUZZARGS="$FUZZARGS" --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" \
        --network=none \
        $flag_aff $flag_ep "$IMG_NAME"
    )
    container_id=$(cut -c-12 <<< $container_id)
    echo_time "Container for $FUZZER/$TARGET/$PROGRAM started in $container_id"
    docker logs -f "$container_id" &
    exit_code=$(docker wait $container_id)
    exit $exit_code
fi
