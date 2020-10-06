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

# build coreutils for every LAVA-M program
cd "$TARGET/repo/LAVA-M"

for program in base64 md5sum uniq who; do
  pushd "$program/coreutils-8.24-lava-safe" &> /dev/null
  ./configure LIBS="-lacl"
  make -j$(nproc)
  cp "src/$program" "$OUT/$program"
  popd &> /dev/null
  mkdir -p "$TARGET/corpus/$program"
  cp -r "$program/fuzzer_input"/* "$TARGET/corpus/$program"
done