#!/bin/bash -e

##
# Pre-requirements:
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# - env PROGRAM: program name (name of binary artifact from $TARGET/build.sh)
# - env ARGS: program launch arguments
# - env SHARED: path to host-local volume where fuzzer findings are saved
# - env POLL: time (in seconds) between polls
# - env TIMEOUT: time to run the campaign
# + env AFFINITY: the CPU to bind the container to (default: no affinity)
##

cleanup() {
	docker rm -f $container_id 1>/dev/null 2>&1
}

trap cleanup EXIT

if [ -z $FUZZER ] || [ -z $TARGET ] || [ -z $PROGRAM ] || [ -z $SHARED ]; then
    echo '$FUZZER, $TARGET, $PROGRAM, and $SHARED must be specified as' \
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

container_id=$(
docker run -dt --volume=`realpath "$SHARED"`:/magma_shared \
        --cap-add=SYS_PTRACE --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
        --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" $flag_aff \
        "$IMG_NAME"
)
container_id=$(cut -c-12 <<< $container_id)
echo_time "Container for $FUZZER/$TARGET/$PROGRAM/$CID started in $container_id"
docker logs -f "$container_id" &
exit_code=$(docker wait $container_id)
exit $exit_code
