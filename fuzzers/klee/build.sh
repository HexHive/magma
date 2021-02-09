#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/uclibc" ] || [ ! -d "$FUZZER/stp" ] || \
   [ ! -d "$FUZZER/klee" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

export CC=clang-9
export CXX=clang++-9
export LLVM_COMPILER=clang

UCLIBC_DIR="$FUZZER/uclibc"
LIBCXX_DIR="$FUZZER/libcxx"
STP_DIR="$FUZZER/stp/install"

mkdir -p "$LIBCXX_DIR"

# build uClibc
(
    cd "$FUZZER/uclibc"
    ./configure --make-llvm-lib
    make -j $(nproc)
)

# build Libc++
(
    export LLVM_VERSION=9
    export SANITIZER_BUILD=
    export BASE="$LIBCXX_DIR"
    export REQUIRES_RTTI=1
    export DISABLE_ASSERTIONS=1
    export ENABLE_DEBUG=0
    export ENABLE_OPTIMIZED=1
    cd "$FUZZER/klee"
    ./scripts/build/build.sh libcxx
)

# build STP
(
    cd "$FUZZER/stp"
    mkdir -p build install && cd build
    cmake .. \
        -DSTATICCOMPILE=ON \
        -DCMAKE_INSTALL_PREFIX="$STP_DIR"
    make -j $(nproc)
    make install
)

# build KLEE
(
    cd "$FUZZER/klee"
    mkdir -p build && cd build
    cmake .. \
        -DENABLE_SOLVER_STP=ON \
        -DSTP_DIR="$STP_DIR" \
        -DENABLE_KLEE_UCLIBC=ON \
        -DENABLE_POSIX_RUNTIME=ON \
        -DKLEE_UCLIBC_PATH="$UCLIBC_DIR" \
        -DENABLE_KLEE_LIBCXX=ON \
        -DKLEE_LIBCXX_DIR="$LIBCXX_DIR/libc++-install-90/" \
        -DKLEE_LIBCXX_INCLUDE_DIR="$LIBCXX_DIR/libc++-install-90/include/c++/v1/" \
        -DENABLE_KLEE_EH_CXX=ON \
        -DKLEE_LIBCXXABI_SRC_DIR="$LIBCXX_DIR/llvm-90/libcxxabi" \
        -DENABLE_UNIT_TESTS=OFF \
        -DENABLE_SYSTEM_TESTS=OFF
    make -j $(nproc)
)

wllvm++ $CXXFLAGS -g -O0 -Xclang -disable-O0-optnone -D__NO_STRING_INLINES \
    -D_FORTIFY_SOURCE=0 -U__OPTIMIZE__ -c "$FUZZER/src/driver.cpp" -fPIC \
    -o "$OUT/driver.o"

echo 'export PATH="$FUZZER/klee/build/bin:$FUZZER/stp/install/bin:$PATH"' >> \
    "$HOME/.bashrc"
echo 'export LLVM_COMPILER=clang' >> "$HOME/.bashrc"
