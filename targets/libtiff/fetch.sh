#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.com/libtiff/libtiff \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 1373f8dacb47d0e256889172c6a5a6dc606f00ba

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
