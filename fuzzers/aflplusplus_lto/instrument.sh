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

export CC="$FUZZER/repo/afl-clang-lto"
export CXX="$FUZZER/repo/afl-clang-lto++"
export AS="/usr/lib/llvm-11/bin/llvm-as"
export RANLIB="/usr/lib/llvm-11/bin/llvm-ranlib"
export AR="/usr/lib/llvm-11/bin/llvm-ar"
export LD="/usr/lib/llvm-11/bin/ld.lld"
export NM="/usr/lib/llvm-11/bin/nm"

export LIBS="-flto=full $LIBS -lstdc++ $FUZZER/repo/examples/aflpp_driver/libAFLDriver.a"

# Build the AFL-only instrumented version
(
    export OUT="$OUT/afl"
    export LDFLAGS="$LDFLAGS -L$OUT"

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# Build the CmpLog instrumented version

(
    export OUT="$OUT/cmplog"
    export LDFLAGS="$LDFLAGS -L$OUT"

    export AFL_LLVM_CMPLOG=1

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
