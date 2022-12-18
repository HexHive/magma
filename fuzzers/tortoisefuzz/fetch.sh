#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

cd $FUZZER

# Get LLVM
wget https://releases.llvm.org/6.0.0/llvm-6.0.0.src.tar.xz
wget https://releases.llvm.org/6.0.0/cfe-6.0.0.src.tar.xz
wget https://releases.llvm.org/6.0.0/compiler-rt-6.0.0.src.tar.xz
wget https://releases.llvm.org/6.0.0/clang-tools-extra-6.0.0.src.tar.xz

tar -xf llvm-6.0.0.src.tar.xz && mv llvm-6.0.0.src "$FUZZER/llvm6"
tar -xf cfe-6.0.0.src.tar.xz && mv cfe-6.0.0.src "$FUZZER/llvm6/tools/clang"
tar -xf compiler-rt-6.0.0.src.tar.xz && mv compiler-rt-6.0.0.src "$FUZZER/llvm6/projects/compiler-rt"
tar -xf clang-tools-extra-6.0.0.src.tar.xz && mv clang-tools-extra-6.0.0.src "$FUZZER/llvm6/tools/clang/tools/extra"
rm -f "$FUZZER/*.tar.xz"

# Get TortoiseFuzz
git clone --no-checkout https://github.com/TortoiseFuzz/TortoiseFuzz "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 2270cab35d2bfa2869120a3352346e285bf3c4ae

# Get afl_driver.cpp from LLVM
wget https://raw.githubusercontent.com/llvm/llvm-project/5feb80e748924606531ba28c97fe65145c65372e/compiler-rt/lib/fuzzer/afl/afl_driver.cpp -O "$FUZZER/repo/afl_driver.cpp"

# Fix: CMake-based build systems fail with duplicate (of main) or undefined references (of LLVMFuzzerTestOneInput)
sed -i '{s/^int main/__attribute__((weak)) &/}' "$FUZZER/repo/afl_driver.cpp"
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' "$FUZZER/repo/afl_driver.cpp"
sed -i '{s/##SIG_AFL_PERSISTENT##/##SIG_AFL_NOT_PERSISTENT##/}' "$FUZZER/repo/afl_driver.cpp"
