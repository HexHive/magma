#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

# We need the version of LLVM which has the LLVMFuzzerRunDriver exposed
cd "$FUZZER/repo/compiler-rt/lib/fuzzer"
for f in *.cpp; do
	clang++ -stdlib=libstdc++ -fPIC -O2 -std=c++11 $f -c &
done && wait
ar r "$OUT/libFuzzer.a" *.o

clang++ $CXXFLAGS -std=c++11 -c "$FUZZER/src/driver.cpp" -fPIC -o "$OUT/driver.o"