#!/bin/bash

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

if [ -z $FUZZER ] || [ -z $TARGET ] || [ -z $PROGRAM ] || [ -z $SHARED ]; then
    echo '$FUZZER, $TARGET, $PROGRAM, and $SHARED must be specified as' \
         'environment variables.'
    exit 1
fi
IMG_NAME="magma/$FUZZER/$TARGET"

if [ ! -z $AFFINITY ]; then
    flag_aff="--cpuset-cpus=$AFFINITY --env=AFFINITY=$AFFINITY"
fi

    docker run -t --volume=`realpath "$SHARED"`:/magma_shared \
        --cap-add=SYS_PTRACE --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
        --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" $flag_aff \
        "$IMG_NAME" \


echo $"Started container $container"
# docker logs $container > ./logs/$FUZZER-$TARGET-$PROGRAM-$AFFINITY-container.log
# code=$(docker wait $container)
# docker rm $container 1>/dev/null 2>&1
# exit $code