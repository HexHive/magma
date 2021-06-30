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

export GOPATH="$FUZZER/repo/go"
export PATH="$GOPATH/bin:$PATH"

export CC="gclang"
export CXX="gclang++"

export CFLAGS="$CFLAGS -fno-discard-value-names"
export CXXFLAGS="$CXXFLAGS -fno-discard-value-names"

export LIBS="$LIBS -l:StandaloneFuzzTargetMain.o -lstdc++"

"$MAGMA/build.sh"
"$TARGET/build.sh"

cd $OUT
source "$TARGET/configrc"

for P in "${PROGRAMS[@]}"; do
    get-bc "./$P"
done

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
