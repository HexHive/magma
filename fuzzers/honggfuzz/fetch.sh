#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/google/honggfuzz.git "$FUZZER/repo"
git -C "$FUZZER/repo" checkout fc6b818c1276056bc565d07edec6ada784cd1670

patch -p1 -d "$FUZZER/repo" << EOF
--- a/linux/trace.c
+++ b/linux/trace.c
@@ -232,8 +232,8 @@ struct user_regs_struct {
 #endif /* defined(__ANDROID__) */
 
 #if defined(__clang__)
-_Pragma("clang Diagnostic push\n");
-_Pragma("clang Diagnostic ignored \"-Woverride-init\"\n");
+_Pragma("clang diagnostic push\n");
+_Pragma("clang diagnostic ignored \"-Woverride-init\"");
 #endif
 
 static struct {
EOF
