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

export PATH="/usr/local/go/bin:$PATH"
export GOPATH="$FUZZER/repo/go"
export PATH="$GOPATH/bin:$PATH"

export LLVM_CC_NAME="clang"
export LLVM_CXX_NAME="clang++"
export CC="gclang"
export CXX="gclang++"

export CFLAGS="$CFLAGS -fsanitize-coverage=trace-pc-guard,no-prune -O2 -fno-omit-frame-pointer -gline-tables-only"
export CXXFLAGS="$CXXFLAGS -fsanitize-coverage=trace-pc-guard,no-prune -O2 -fno-omit-frame-pointer -gline-tables-only"

export LIBS="$LIBS -l:afl_llvm_rt_driver.a -lstdc++"

"$MAGMA/build.sh"
"$TARGET/build.sh"

cd $OUT
source "$TARGET/configrc"

for P in "${PROGRAMS[@]}"; do
  get-bc "$P"

  llvm-dis "$P.bc"
  python3 "$FUZZER/repo/kscheduler/afl_integration/build_example/fix_long_fun_name.py" "$P.ll"
  mkdir -p "$OUT/cfg_out_$P"
  cd "$OUT/cfg_out_$P"
  opt-11 -dot-cfg "$OUT/${P}_fix.ll"
  for f in $(ls -a | grep '^\.*' | grep dot); do mv $f ${f:1}; done

  cd $OUT
  python3 "$FUZZER/repo/kscheduler/afl_integration/build_example/gen_graph.py" \
      "${P}_fix.ll" "cfg_out_$P"
done

# NOTE: We pass $OUT directly to the target build.sh script, since the artifact
#       itself is the fuzz target. In the case of Angora, we might need to
#       replace $OUT by $OUT/fast and $OUT/track, for instance.
