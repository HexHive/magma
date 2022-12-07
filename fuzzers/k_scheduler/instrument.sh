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

ORIG_CFLAGS=$CFLAGS
ORIG_CXXFLAGS=$CXXFLAGS
ORIG_LDFLAGS=$LDFLAGS
ORIG_LIBS=$LIBS

export PATH="/usr/local/go/bin:$PATH"
export GOPATH="$FUZZER/repo/go"
export PATH="$GOPATH/bin:$PATH"

(
  export CFLAGS="$ORIG_CFLAGS -O2 -fsanitize-coverage=trace-pc-guard,no-prune -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link"
  export CXXFLAGS="$ORIG_CXXFLAGS -O2 -fsanitize-coverage=trace-pc-guard,no-prune -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link"
  export LDFLAGS="$ORIG_LDFLAGS -fsanitize=fuzzer-no-link"
  export LIBS="$ORIG_LIBS -l:afl_driver.o -l:afl-llvm-rt.o -lstdc++"

  export LLVM_CC_NAME="clang"
  export LLVM_CXX_NAME="clang++"
  export CC="gclang"
  export CXX="gclang++"

  "$MAGMA/build.sh"
  "$TARGET/build.sh"

  cd $OUT
  source "$TARGET/configrc"

  for P in "${PROGRAMS[@]}"; do
    mkdir -p "$OUT/${P}_out"
    cd "$OUT/${P}_out"

    get-bc -o "$P.bc" "$OUT/$P"
    llvm-dis "$P.bc"
    python3 "$FUZZER/repo/kscheduler/afl_integration/build_example/fix_long_fun_name.py" "$P.ll"
    opt-11 -dot-cfg "${P}_fix.ll"

    mkdir -p cfgs
    for f in $(ls -a | grep '^\.*' | grep dot); do mv $f "cfgs/${f:1}"; done

    python3 "$FUZZER/repo/kscheduler/afl_integration/build_example/gen_graph.py" \
        "${P}_fix.ll" cfgs

    # We need to configure the AFL map so that it fits all of the CFG edges. So
    # save the size required for this program
    MAP_SIZE="$(wc -l < katz_cent)"
    MAP_SIZE_POW2=$(python3 -c "from math import ceil, log2; print('%d' % ceil(log2(${MAP_SIZE})))")
    echo $MAP_SIZE_POW2 >> "$OUT/map_sizes"
  done
)

# Determine the largest map size (amongst all the programs) and recompile AFL
# and the target with that map size
MAP_SIZE_POW2=$(sort -nr "$OUT/map_sizes" | head -n1)
if [[ "${MAP_SIZE_POW2}" -gt "16" ]]; then
  (
    export CFLAGS="-DMAP_SIZE_POW2=${MAP_SIZE_POW2}"
    "$FUZZER/build.sh"

    export CFLAGS="$ORIG_CFLAGS -O2 -fsanitize-coverage=trace-pc-guard,no-prune -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link"
    export CXXFLAGS="$ORIG_CXXFLAGS -O2 -fsanitize-coverage=trace-pc-guard,no-prune -fno-omit-frame-pointer -gline-tables-only -fsanitize=fuzzer-no-link"
    export LDFLAGS="$ORIG_LDFLAGS -fsanitize=fuzzer-no-link"
    export LIBS="$ORIG_LIBS -l:afl_driver.o -l:afl-llvm-rt.o -lstdc++"

    export LLVM_CC_NAME="clang"
    export LLVM_CXX_NAME="clang++"
    export CC="gclang"
    export CXX="gclang++"

    "$TARGET/build.sh"
  )
fi

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
