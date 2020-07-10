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

export CC="$FUZZER/repo/afl-clang-fast"
export CXX="$FUZZER/repo/afl-clang-fast++"
export AS="$FUZZER/repo/afl-as"

export LIBS="$LIBS -l:afl_driver.o -lstdc++"

# Build the AFL-only instrumented version
(
    export OUT="$OUT/afl"
    export LDFLAGS="$LDFLAGS -L$OUT"

    export AFL_LLVM_INSTRUMENT=CLASSIC
    export AFL_LLVM_CTX=1
    export AFL_LLVM_SKIP_NEVERZERO=1

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# Build the CmpLog instrumented version

(
    export OUT="$OUT/cmplog"
    export LDFLAGS="$LDFLAGS -L$OUT"
    # export CFLAGS="$CFLAGS -DMAGMA_DISABLE_CANARIES"

    export AFL_LLVM_INSTRUMENT=CLASSIC
    export AFL_LLVM_CTX=1
    export AFL_LLVM_SKIP_NEVERZERO=1
    export AFL_LLVM_CMPLOG=1

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.