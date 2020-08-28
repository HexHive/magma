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

export LIBS="$LIBS -l:driver.o -lstdc++"

export CC="$FUZZER/symcc/build/symcc"
export CXX="$FUZZER/symcc/build/sym++"

export SYMCC_LIBCXX_PATH="$FUZZER/llvm/libcxx_symcc_install"
export SYMCC_NO_SYMBOLIC_INPUT=1
mkdir -p /tmp/output

"$MAGMA/build.sh"
"$TARGET/build.sh"
