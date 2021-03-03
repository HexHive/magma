#!/bin/bash

##
# Pre-requirements:
# - $1: path to captainrc (default: ./captainrc)
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# - env PROGRAM: program name (name of binary artifact from $TARGET/build.sh)
# - env ARGS: program launch arguments
# - env CID: campaign ID
# - env SHARED: path to host-local volume where fuzzer findings are saved
# - env POCDIR: path to the directory where minimized corpora will be saved
# - env LOCKDIR: path to the locks directory
##

if [ -z $1 ]; then
    set -- "./captainrc"
fi

# load the configuration file (captainrc)
set -a
source "$1"
set +a

mutex()
{
    ##
    # Pre-requirements:
    # - $1: the mutex ID (file descriptor)
    # - $2..N: command to run
    ##
    trap 'rm -f "$LOCKDIR/$mux"' EXIT RETURN
    mux=$1
    shift
    (
      flock -xF 200 &> /dev/null
      "${@}"
    ) 200>"$LOCKDIR/$mux"
}
export -f mutex

cleanup() {
    if [ ! -z "$container_id" ]; then
        docker rm -f $container_id 1>/dev/null 2>&1
    fi
}

trap cleanup EXIT

IMG_NAME="magma/$FUZZER/$TARGET"

container_id=$(
docker run -dt --entrypoint bash --volume=`realpath "$SHARED"`:/magma_shared \
    --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
    "$IMG_NAME"
)

docker exec -i $container_id bash << 'EOF'
delete=("$SHARED"/*)
mkdir -p "$SHARED/orig" "$SHARED/min"
MODE=cov $FUZZER/findings.sh | while read file; do
    delete=( "${delete[@]/$file}" )
    cp "$file" "$SHARED/orig"
done
rm -rf ${delete[@]}

# Minimize the corpus according to the generator's view (for one-sided overlap)
export CORPUS_IN="$SHARED/orig"
export CORPUS_OUT="$SHARED/min"
(cd /tmp && "$FUZZER"/minimize.sh)
find "$SHARED/min" -maxdepth 1 -type f -exec mv {} "$SHARED" \;
rm -rf "$SHARED/min" "$SHARED/orig"
EOF

docker rm -f $container_id 1>/dev/null 2>&1

echo_time "Processing $IMG_NAME/$PROGRAM/$CID"
export BASEFUZZER=$FUZZER
for FUZZER in "${FUZZERS[@]}"; do
    export FUZZER

    outdir="$POCDIR/$TARGET/$PROGRAM/$CID/$BASEFUZZER/$FUZZER"
    mkdir -p "$outdir"

    if [ "$FUZZER" = "$BASEFUZZER" ]; then
        # skip minimization because it's already done above
        find "$SHARED" -maxdepth 1 -type f -exec cp {} "$outdir" \;
        continue
    fi

    # build the Docker image
    IMG_NAME="magma/$FUZZER/$TARGET"
    echo_time "Building $IMG_NAME"
    if ! mutex 'magma_build_cov' "$MAGMA"/tools/captain/build.sh &> \
        "${LOGDIR}/${FUZZER}_${TARGET}_build.log"; then
        echo_time "Failed to build $IMG_NAME. Check build log for info."
        continue
    fi

    container_id=$(
    docker run -dt --entrypoint bash \
        --volume=`realpath "$SHARED"`:/magma_shared/in \
        --volume=`realpath "$outdir"`:/magma_shared/out \
        --env=CORPUS_IN=/magma_shared/in --env=CORPUS_OUT=/magma_shared/out \
        --env=PROGRAM="$PROGRAM" --env=ARGS="$ARGS" \
        "$IMG_NAME"
    )

    docker exec $container_id bash -c 'echo amgam | sudo -S chown magma:magma /magma_shared/in /magma_shared/out &> /dev/null'

    docker exec $container_id bash -c 'cd /tmp && $FUZZER/minimize.sh'

    docker rm -f $container_id 1>/dev/null 2>&1
done
container_id=""

cd "$POCDIR/$TARGET/$PROGRAM/$CID/$BASEFUZZER"
find . -mindepth 1 -maxdepth 1 -type d |
while read OBSERVER; do
    corpus_size=$(ls "$OBSERVER" | wc -l)
    OBSERVER=$(basename $OBSERVER)

    echo $TARGET, $PROGRAM, $CID, $BASEFUZZER, $OBSERVER, $corpus_size >> \
        ./stats
done
shopt -s extglob
rm -rf !(stats)
shopt -u extglob
exit 0

# After further thought, the following part is invalid. Distinct seeds can yield
# identical coverage, so a lack of overlap is not indicative of distinct
# coverage views

cd "$POCDIR/$TARGET/$PROGRAM/$CID/$BASEFUZZER"
find . -mindepth 1 -maxdepth 1 -type d |
while read OBSERVER; do
    OBSERVER=$(basename $OBSERVER)
    if [ "$OBSERVER" = "$BASEFUZZER" ]; then
        var_identical=1
    else
        values="$(diff -srq $BASEFUZZER $OBSERVER |
            sed -nE 's/^Only in (\w+).*?:.*$|^.*(identical)$/\1\2/p' |
            sort |
            uniq -c |
            sed -nE 's/^\s*([0-9]+) (\w+)$/var_\2=\1/p')"
        eval "$values"
    fi

    varname_BASEFUZZER=var_$BASEFUZZER
    varname_OBSERVER=var_$OBSERVER
    varname_IDENTICAL=var_identical
    echo $TARGET, $PROGRAM, $CID, $BASEFUZZER, $OBSERVER, \
         ${!varname_BASEFUZZER:-0}, ${!varname_OBSERVER:-0}, ${!varname_IDENTICAL:-0} >> \
        ./stats
done
