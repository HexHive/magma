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

export WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

pushd "$TARGET/freetype2"
./autogen.sh
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc) clean
make -j$(nproc)
make install

mkdir -p "$WORK/poppler"
cd "$WORK/poppler"
rm -rf *

EXTRA=""
test -n "$AR" && EXTRA="$EXTRA -DCMAKE_AR=$AR"
test -n "$RANLIB" && EXTRA="$EXTRA -DCMAKE_RANLIB=$RANLIB"

cmake "$TARGET/repo" \
  $EXTRA \
  -DCMAKE_BUILD_TYPE=debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DFONT_CONFIGURATION=generic \
  -DBUILD_GTK_TESTS=OFF \
  -DBUILD_QT5_TESTS=OFF \
  -DBUILD_CPP_TESTS=OFF \
  -DENABLE_LIBPNG=ON \
  -DENABLE_LIBTIFF=ON \
  -DENABLE_LIBJPEG=ON \
  -DENABLE_SPLASH=ON \
  -DENABLE_UTILS=ON \
  -DWITH_Cairo=ON \
  -DENABLE_CMS=none \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_GLIB=OFF \
  -DENABLE_GOBJECT_INTROSPECTION=OFF \
  -DENABLE_QT5=OFF \
  -DENABLE_LIBCURL=OFF \
  -DWITH_NSS3=OFF \
  -DFREETYPE_INCLUDE_DIRS="$WORK/include/freetype2" \
  -DFREETYPE_LIBRARY="$WORK/lib/libfreetype.a" \
  -DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" \
  -DCMAKE_EXE_LINKER_FLAGS_INIT="$LIBS"
make -j$(nproc) poppler poppler-cpp pdfimages pdftoppm
EXTRA=""

cp "$WORK/poppler/utils/"{pdfimages,pdftoppm} "$OUT/"
$CXX $CXXFLAGS -std=c++11 -I"$WORK/poppler/cpp" -I"$TARGET/repo/cpp" \
    "$TARGET/src/pdf_fuzzer.cc" -o "$OUT/pdf_fuzzer" \
    "$WORK/poppler/cpp/libpoppler-cpp.a" "$WORK/poppler/libpoppler.a" \
    "$WORK/lib/libfreetype.a" $LDFLAGS $LIBS -ljpeg -lz \
    -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread
