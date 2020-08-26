#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.com/libtiff/libtiff \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 1373f8dacb47d0e256889172c6a5a6dc606f00ba

git clone --no-checkout https://github.com/madler/zlib \
    "$TARGET/zlib"
git -C "$TARGET/zlib" checkout cacf7f1d4e3d44d871b605da3b647f07d718623f

git clone --no-checkout https://github.com/libjpeg-turbo/libjpeg-turbo \
    "$TARGET/libjpeg-turbo"
git -C "$TARGET/libjpeg-turbo" checkout b443c541b9a6fdcac214f9f003de0aa13e480ac1

git clone --no-checkout https://www.cl.cam.ac.uk/~mgk25/git/jbigkit \
    "$TARGET/jbigkit"
git -C "$TARGET/jbigkit" checkout dce101373d87445ed55a385fddad02d8a8751de4

# Uncomment default CC and CFLAGS from the build of jbigkit
patch -p1 -d "$TARGET/jbigkit" << EOF
--- a/Makefile
+++ b/Makefile
@@ -1,10 +1,10 @@
 # Unix makefile for JBIG-KIT
 
 # Select an ANSI/ISO C compiler here, GNU gcc is recommended
-CC = gcc
+# CC = gcc
 
 # Options for the compiler: A high optimization level is suggested
-CFLAGS = -O2 -W -Wno-unused-result
+# CFLAGS = -O2 -W -Wno-unused-result
 # CFLAGS = -O -g -W -Wall -Wno-unused-result -ansi -pedantic # -DDEBUG
 
 export CC CFLAGS
EOF

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"