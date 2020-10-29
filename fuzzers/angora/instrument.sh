#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env MAGMA: path to Magma support files
# - env OUT: path to directory where artifacts are stored
# - env CFLAGS and CXXFLAGS must be set to link against Magma instrumentation
##

export PATH="$FUZZER/repo/llvm_install/clang+llvm/bin:$PATH"
export LD_LIBRARY_PATH="$FUZZER/repo/llvm_install/clang+llvm/lib:$FUZZER/repo/bin/lib:$LD_LIBRARY_PATH"

export CC="$FUZZER/repo/bin/angora-clang"
export CXX="$FUZZER/repo/bin/angora-clang++"

# Build fast target
(
    export OUT="$OUT/angora-fast"
    export LDFLAGS="$LDFLAGS -L$OUT"

    export USE_FAST=1
    export LIBS="$LIBS -l:angora_driver.o -lstdc++"

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# Create taint rule list for track target
(
    cd "$OUT/angora-fast"
    source "$TARGET/configrc"

    # Don't create taint rule list for the following libraries
    LIB_BLACKLIST=(linux-vdso libc++abi libgcc_s libc ld-linux-x86-64)

    # Discard taint for all linked libraries
    for P in "${PROGRAMS[@]}"; do
        for L in $(ldd "./$P" | awk 'NF == 4 {print $3}; NF == 2 {print $1}'); do
            L=$(readlink -f $L)
            LIB_NAME=$(basename $L | sed 's/\.so[.0-9]*//')
            if [[ ! " ${LIB_BLACKLIST[@]} " =~ " $LIB_NAME " ]]; then
                "$FUZZER/repo/tools/gen_library_abilist.sh" $L discard >> "$TARGET/repo/abilist.txt"
            fi
        done
    done
)

# Build track target
(
    export OUT="$OUT/angora-track"
    export LDFLAGS="$LDFLAGS -L$OUT -L$FUZZER/repo/bin/lib"
    export LIBS="$LIBS -l:angora_driver.o -lstdc++"

    export USE_TRACK=1
    export ANGORA_TAINT_RULE_LIST="$TARGET/repo/abilist.txt"

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
