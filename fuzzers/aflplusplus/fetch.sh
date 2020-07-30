#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git "$FUZZER/repo"

# Fix: CMake-based build systems fail with duplicate or undefined references
sed -i '{s/^int main/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.cpp
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.cpp
cat >> $FUZZER/repo/examples/aflpp_driver/aflpp_driver.cpp << EOF
extern "C" __attribute__((weak))
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  assert(false && "LLVMFuzzerTestOneInput should not be implemented in afl_driver");
  return 0;
}
EOF