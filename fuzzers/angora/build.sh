#!/bin/bash
set -ex

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "$FUZZER/repo"

# Install Rust
export RUSTUP_HOME="$HOME/.cargo/"
export CARGO_HOME="$HOME/.cargo/"
export PATH="$CARGO_HOME/bin:$PATH"
./build/install_rust.sh

# Install LLVM
mkdir -p "$FUZZER/repo/llvm_install"
PREFIX="$FUZZER/repo/llvm_install" ./build/install_llvm.sh

# Build Angora
export PATH="$FUZZER/repo/llvm_install/clang+llvm/bin:$PATH"
export LD_LIBRARY_PATH="$FUZZER/repo/llvm_install/clang+llvm/lib:$LD_LIBRARY_PATH"
./build/build.sh

# Compile angora_driver.c
mkdir -p "$OUT/angora-fast"
USE_FAST=1 "./bin/angora-clang" $CFLAGS -c "angora_driver.c" -fPIC -o "$OUT/angora-fast/angora_driver.o"

mkdir -p "$OUT/angora-track"
USE_TRACK=1 "./bin/angora-clang" $CFLAGS -c "angora_driver.c" -fPIC -o "$OUT/angora-track/angora_driver.o"
