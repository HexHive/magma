#!/bin/bash -e

##
# Pre-requirements:
# + $1: path to captainrc (default: ./captainrc)
##

if [ -z $1 ]; then
    set -- "./captainrc"
fi

# load the configuration file (captainrc)
set -a
source "$1"
set +a

if [ -z $WORKDIR ] || [ -z $REPEAT ]; then
    echo '$WORKDIR and $REPEAT must be specified as environment variables.'
    exit 1
fi
MAGMA=${MAGMA:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" >/dev/null 2>&1 \
    && pwd)"}
export MAGMA
source "$MAGMA/tools/captain/common.sh"

WORKERS=${WORKERS:-$(( $(nproc) - 2 ))}
WORKERPOOLR=($(lscpu -b --parse | sed '/^#/d' | cut -d, -f1))
export WORKERPOOL="${WORKERPOOLR[@]:0:WORKERS}"

TMPFS_SIZE=${TMPFS_SIZE:-50g}
export POLL=${POLL:-5}
export TIMEOUT=${TIMEOUT:-1m}

WORKDIR="$(realpath "$WORKDIR")"
export LOGDIR="$WORKDIR/log"
export POCDIR="$WORKDIR/poc"
mkdir -p "$LOGDIR"
mkdir -p "$POCDIR"

get_next_cid()
{
    ##
    # Pre-requirements:
    # - $1: the directory where campaigns are stored
    ##
    shopt -s nullglob
    campaigns=("$1"/*)
    if [ ${#campaigns[@]} -eq 0 ]; then
        echo 0
        mkdir -p "$1/0"
    else
        cids=($(sort -n < <(basename -a "${campaigns[@]}")))
        for ((i=0;;i++)); do
            if [ -z ${cids[i]} ] || [ ${cids[i]} -ne $i ]; then
                echo $i
                # ensure the directory is created to prevent races
                mkdir -p "$1/$i"
                break
            fi
        done
    fi
}
export -f get_next_cid

start_campaign()
{
    ##
    # Pre-requirements:
    # - env AFFINITY
    # - env FUZZER
    # - env TARGET
    # - env PROGRAM
    # - env ARGS
    ##
    CACHEDIR="$WORKDIR/cache/$FUZZER/$TARGET/$PROGRAM"
    export CID=$(sem --id magma_cid --fg -j 1 -u \
            get_next_cid "$CACHEDIR")
    export SHARED="$CACHEDIR/$CID"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"

    echo_time "Container $FUZZER/$TARGET/$PROGRAM/$CID started on CPU $AFFINITY"
    "$MAGMA"/tools/captain/start.sh &> \
        "${LOGDIR}/${FUZZER}_${TARGET}_${PROGRAM}_${CID}_container.log"
    echo_time "Container $FUZZER/$TARGET/$PROGRAM/$CID stopped"

    "$MAGMA"/tools/captain/extract.sh

    ARDIR="$WORKDIR/ar/$FUZZER/$TARGET/$PROGRAM"
    mkdir -p "$ARDIR"
    CID=$(sem --id magma_cid --fg -j 1 -u \
            get_next_cid "$ARDIR")
    if [ -z $NO_ARCHIVE ]; then
        # only one tar job runs at a time, to prevent out-of-storage errors
        sem --id "magma_tar" --fg -j 1 \
          tar -cf "${ARDIR}/${CID}/${CID}.tar" -C "$SHARED" . &>/dev/null && \
        rm -rf "$SHARED"
    else
        rm -rf "${ARDIR}/${CID}" && mv "$SHARED" "${ARDIR}/${CID}"
    fi
}
export -f start_campaign

start_ex()
{
    ##
    # Pre-requirements:
    # - $1: NUMCPUS
    # - $2: CPUSET
    # - $3+: COMMAND
    ##
    NUMCPUS=$1
    CPUSET=$2
    COMMAND=("${@:3}")
    if [ $NUMCPUS -gt 0 ]; then
        while true; do
            for i in $WORKERPOOL; do
                if [ -d ~/.parallel/semaphores/"id-magma_cpu_$i" ] || \
                        ! sem -u --id "magma_cpu_$i" -j 1 --st -1 --fg \
                        start_ex $((NUMCPUS - 1)) "$CPUSET,$i" \
                        ${COMMAND[@]}; then
                    continue
                else
                    exit 0
                fi
            done
            sleep 1 # yet another hacky fix...
        done
    else
        # release CPU allocation lock (hacky :/)
        sem --id "magma" --st 1 rm -rf ~/.parallel/semaphores/id-magma &> /dev/null
        # GNU Parallel does not re-aquire the mutex when it steals it, thus the
        # following statement does not do the intended task of releasing the
        # mutex after stealing it:
        # sem --id "magma" --st 1
        # Hence, we have to delete the metadata used by GNU Parallel, as above

        export AFFINITY=$(cut -d',' -f2- <<< $CPUSET)
        ${COMMAND[@]}
        exit 0
    fi
}
export -f start_ex

contains_element () {
    local e match="$1"
    shift
    for e; do [[ "$e" == "$match" ]] && return 0; done
    return 1
}

get_var_or_default() {
    ##
    # Pre-requirements:
    # - $1: variable format
    # - $2..N: placeholders
    ##
    pattern="$1"
    shift

    name="$(eval echo $pattern)"
    name="${name}[@]"
    value="${!name}"
    if [ -z $value ] || [ ${#value[@]} -eq 0 ]; then
        set -- "DEFAULT" "${@:2}"
        name="$(eval echo $pattern)"
        name="${name}[@]"
        value="${!name}"
    fi
    echo "${value[@]}"
}

# clear any stuck semaphores
sem --id "magma" --st 1 rm -rf ~/.parallel/semaphores/id-magma*

# set up a RAM-backed fs for fast processing of canaries and crashes
mkdir -p "$WORKDIR/cache"
mkdir -p "$WORKDIR/ar"
if [ -z $CACHE_ON_DISK ]; then
    echo_time "Obtaining sudo permissions to mount tmpfs"
    if mountpoint -q -- "$WORKDIR/cache"; then
        sudo umount -f "$WORKDIR/cache"
    fi
    sudo mount -t tmpfs -o size=$TMPFS_SIZE,uid=$(id -u $USER),gid=$(id -g $USER) \
        tmpfs "$WORKDIR/cache"
fi

# initialize default parameters
pushd "$MAGMA/targets" &> /dev/null
shopt -s nullglob
DEFAULT_TARGETS=(*)
shopt -u nullglob

for TARGET in "${DEFAULT_TARGETS[@]}"; do
    source "$MAGMA/targets/$TARGET/configrc"
    PROGRAMS_str="${PROGRAMS[@]}"
    declare -a DEFAULT_${TARGET}_PROGRAMS="($PROGRAMS_str)"

    for PROGRAM in "${PROGRAMS[@]}"; do
        varname="${PROGRAM}_ARGS"
        declare DEFAULT_${TARGET}_${PROGRAM}_ARGS="${!varname}"
    done
done
popd &> /dev/null

# schedule campaigns
for FUZZER in "${FUZZERS[@]}"; do
    export FUZZER

    TARGETS=($(get_var_or_default '$1_TARGETS' $FUZZER))
    for TARGET in "${TARGETS[@]}"; do
        export TARGET

        # build the Docker image
        IMG_NAME="magma/$FUZZER/$TARGET"
        echo_time "Building $IMG_NAME"
        "$MAGMA"/tools/captain/build.sh &> "${LOGDIR}/${FUZZER}_${TARGET}_build.log"

        PROGRAMS=($(get_var_or_default '$1_$2_PROGRAMS' $FUZZER $TARGET))
        for PROGRAM in "${PROGRAMS[@]}"; do
            export PROGRAM
            export ARGS="$(get_var_or_default '$1_$2_$3_ARGS' $FUZZER $TARGET $PROGRAM)"

            echo_time "Starting campaigns for $PROGRAM $ARGS"
            for ((i=0; i<$REPEAT; i++)); do
                NUMCPUS=1 # TODO this can later be read from fuzzer config
                # acquire CPU allocation lock
                sem --id "magma" -u \
                    start_ex $NUMCPUS "-1" \
                    start_campaign
            done
        done
    done
done

for i in $WORKERPOOL; do
    sem --id "magma_cpu_$i" --wait
done

if [ -z $CACHE_ON_DISK ]; then
    echo_time "Obtaining sudo permissions to umount tmpfs"
    sudo umount "$WORKDIR/cache"
fi
