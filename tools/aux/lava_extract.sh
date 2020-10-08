#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# - env PROGRAM: program name (name of binary artifact from $TARGET/build.sh)
# - env ARGS: program launch arguments
# - env SHARED: path to host-local volume where fuzzer findings are saved
# - env POCDIR: path to the directory where faulty test cases will be saved
# - env BEGIN: unix epoch timestamp indicating when experiment was started
##

cleanup() {
    docker rm -f $container_id 1>/dev/null 2>&1
}

trap cleanup EXIT

IMG_NAME="magma/$FUZZER/$TARGET"

container_id=$(
docker run -dt --entrypoint bash --volume=`realpath "$SHARED"`:/magma_shared \
    --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
    "$IMG_NAME"
)

docker exec $container_id bash -c '$FUZZER/findings.sh' | \
while read file; do
    timestamp=$(stat -c %Y "$file")
    ttb=$(( timestamp - BEGIN ))
    bug="$(docker exec $container_id \
        bash -c '$FUZZER/runonce.sh '"'$file'"' | grep -aoPm1 "Successfully triggered bug \K(\d+)"')"

    poc_name="${ttb}_${FUZZER}_${TARGET}_${PROGRAM}"
    if [ ! -z "$bug" ]; then
        poc_name="${poc_name}_$bug"
    else
        poc_name="${poc_name}_NEW"
    fi

    poc=$(mktemp --tmpdir="$POCDIR" "${poc_name}.XXX")
    docker cp "$container_id:$file" "$poc"
done
