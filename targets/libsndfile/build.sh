#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

# build the libpng library
cd "$TARGET/repo"
#sed -i "s@FUZZ_LDADD = libstandaloneengine.la@FUZZ_LDADD = ossfuzz/libstandaloneengine.la@" Makefile.am
./autogen.sh
./configure --disable-shared --enable-ossfuzzers
make -j$(nproc) clean
make -j$(nproc) V=1

cp -v ossfuzz/sndfile_fuzzer $OUT/