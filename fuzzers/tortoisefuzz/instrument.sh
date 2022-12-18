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

cd $OUT

export PATH="$FUZZER/llvm-install/bin:$PATH"
export LD_LIBRARY_PATH="$FUZZER/llvm-install/lib:$LD_LIBRARY_PATH"

export ORIG_OUT="$OUT"
export ORIG_LDFLAGS="$LDFLAGS"

# Build Magma lib
export CC=clang
export CXX=clang++
"$MAGMA/build.sh"

# Build target
export LIBS="$LIBS -l:afl_driver.o -lstdc++"
export AFL_CC=clang
export AFL_CXX=clang++

for METRIC in bb func loop; do
    mkdir -p "${ORIG_OUT}/${METRIC}_metric"

    export OUT="${ORIG_OUT}/${METRIC}_metric"
    export CC="$FUZZER/repo/${METRIC}_metric/afl-clang-fast"
    export CXX="$FUZZER/repo/${METRIC}_metric/afl-clang-fast++"
    export LDFLAGS="$LDFLAGS -L$ORIG_OUT -L$OUT"

    "$TARGET/build.sh"
done

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
