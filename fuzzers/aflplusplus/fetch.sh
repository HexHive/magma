#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AFLplusplus/AFLplusplus.git \
    "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 4a51cb71fb8785325dedac693cdea4648f6e5279

# Fix: CMake-based build systems fail with duplicate or undefined references
sed -i '{s/^int main/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.cpp
cat >> $FUZZER/repo/examples/aflpp_driver/aflpp_driver.cpp << EOF
extern "C" __attribute__((weak))
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  assert(false && "LLVMFuzzerTestOneInput should not be implemented in afl_driver");
  return 0;
}
EOF
