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

#build the php library
cd "$TARGET/repo"
./configure \
    --enable-fuzzer \
    --with-pic \
    --enable-debug-assertions \
    --enable-exif \
make -j$(nproc) clean
make -j$(nproc) 


#Copy the generated seeds to the artifacts location
cp sapi/fuzzer/php-fuzz-exif $OUT/$


