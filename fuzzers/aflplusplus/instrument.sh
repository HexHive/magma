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

OUT_ORG="$OUT"
LDFLAGS_ORG="$LDFLAGS"

# Build the AFL-only instrumented version
export OUT="$OUT_ORG/afl"
export LDFLAGS="$LDFLAGS_ORG -L$OUT"

"$MAGMA/build.sh"
"$TARGET/build.sh"

# # Build the CmpLog instrumented version
#
# WARNING: CmpLog has been disabled because launching the monitor before AFL
#   "stabilizes" causes the fuzzer to segfault. Pending further investigation.
#
# export AFL_LLVM_CMPLOG=1
# export OUT="$OUT_ORG/cmplog"
# export LDFLAGS="$LDFLAGS_ORG -L$OUT"
# export CFLAGS="$CFLAGS -DMAGMA_DISABLE_CANARIES"

# "$MAGMA/build.sh"
# "$TARGET/build.sh"

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.