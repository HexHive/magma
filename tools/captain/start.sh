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
# - env CID: numeric campaign identifier
# + env AFFINITY: the CPU to bind the container to (default: no affinity)
# + env LOGSDIR: path to logs directory
##

if [ -z $FUZZER ] || [ -z $TARGET ] || [ -z $PROGRAM ] || [ -z $SHARED ]; then
    echo '$FUZZER, $TARGET, $PROGRAM, and $SHARED must be specified as' \
         'environment variables.'
    exit 1
fi

if [ -z $LOGSDIR ]; then
    CONTAINER_LOGFILE="/dev/null"
else
    CONTAINER_LOGFILE=""$LOGSDIR"/"$FUZZER"_"$TARGET"_"$PROGRAM"_"$CID"_container.log"
fi

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
exit_code=$(docker wait $container_id)
docker logs "$container_id" &> "$CONTAINER_LOGFILE"
echo_time "Container for $FUZZER/$TARGET/$PROGRAM/$CID exited with $exit_code"
docker rm $container_id 1>/dev/null 2>&1
exit $exit_code
