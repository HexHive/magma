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

export LIBS="$LIBS -lstdc++"

# Build eclipser target
(
    export OUT="$OUT/eclipser"
    export LDFLAGS="$LDFLAGS -L$OUT"

    export CC="clang"
    export CXX="clang++"
    export LIBS="$LIBS -l:standalone_driver.o"

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# Build AFL target
(
    export OUT="$OUT/afl"
    export CFLAGS="$CFLAGS -fsanitize-coverage=trace-pc-guard"
    export CXXFLAGS="$CXXFLAGS -fsanitize-coverage=trace-pc-guard"
    export LDFLAGS="$LDFLAGS -L$OUT"

    export CC="clang"
    export CXX="clang++"
    export LIBS="$LIBS -lafl"

    "$MAGMA/build.sh"
    "$TARGET/build.sh"
)

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
