#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://gitlab.com/libtiff/libtiff \
    --depth 1 --branch master \
    "$TARGET/repo"
git clone https://github.com/madler/zlib \
    --depth 1 --branch master \
    "$TARGET/zlib"
git clone https://github.com/libjpeg-turbo/libjpeg-turbo \
    --depth 1 --branch master \
    "$TARGET/libjpeg-turbo"
git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit \
    "$TARGET/jbigkit"

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