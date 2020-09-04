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

export CC="wllvm"
export CXX="wllvm++"
export LLVM_COMPILER=clang

export CFLAGS="$CFLAGS -g -O0 -Xclang -disable-O0-optnone -D__NO_STRING_INLINES -D_FORTIFY_SOURCE=0 -U__OPTIMIZE__"
export CXXFLAGS="$CXXFLAGS -g -O0 -Xclang -disable-O0-optnone -D__NO_STRING_INLINES -D_FORTIFY_SOURCE=0 -U__OPTIMIZE__"

export CFLAGS="$CFLAGS -include $FUZZER/klee/include/klee/klee.h"
export CXXFLAGS="$CXXFLAGS -include $FUZZER/klee/include/klee/klee.h"
export LDFLAGS="$LDFLAGS -L$FUZZER/klee/build/lib"
export LIBS="$LIBS -l:libkleeRuntest.so.1.0"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$FUZZER/klee/build/lib"

export LIBS="$LIBS -l:driver.o -lstdc++"

"$MAGMA/build.sh"
"$TARGET/build.sh"

(
    cd "$OUT"
    source "$TARGET/configrc"
    for p in "${PROGRAMS[@]}"; do
        extract-bc "./$p"
    done
)

echo 'export LD_LIBRARY_PATH="$FUZZER/klee/build/lib:$LD_LIBRARY_PATH"' >> "$HOME/.bashrc"