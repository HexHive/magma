#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AFLplusplus/AFLplusplus.git \
    "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 986af28df27016813abdfdde8bdedda1f571703c

# Fix: CMake-based build systems fail with duplicate (of main) or undefined references (of LLVMFuzzerTestOneInput)
sed -i '{s/^int main/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.c
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.c
cat >> $FUZZER/repo/examples/aflpp_driver/aflpp_driver.c << EOF
__attribute__((weak))
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  // assert(0 && "LLVMFuzzerTestOneInput should not be implemented in afl_driver");
  return 0;
}
EOF