#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

export PATH="/usr/local/go/bin:$PATH"
export GOPATH="$FUZZER/repo/go"

mkdir -p $GOPATH
go install github.com/SRI-CSL/gllvm/cmd/...@latest

git clone --no-checkout https://github.com/Dongdongshe/K-Scheduler "$FUZZER/repo/kscheduler"
git -C "$FUZZER/repo/kscheduler" checkout 36bc5aa658fa7c9716aee08a8ff22419f28e3fe9

sed -i '{s/^int main/__attribute__((weak)) &/}' \
    "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' \
    "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"
sed -i '{s/##SIG_AFL_PERSISTENT##/##SIG_AFL_NOT_PERSISTENT##/}' \
    "$FUZZER/repo/kscheduler/libfuzzer_integration/llvm_11.0.1/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"

patch -p1 -d "$FUZZER/repo/kscheduler" << EOF
index 8a09b93b0..794682b86 100644
--- a/afl_integration/afl-2.52b_kscheduler/config.h
+++ b/afl_integration/afl-2.52b_kscheduler/config.h
@@ -315,7 +315,9 @@
    problems with complex programs). You need to recompile the target binary
    after changing this - otherwise, SEGVs may ensue. */

+#if !defined(MAP_SIZE_POW2)
 #define MAP_SIZE_POW2       16
+#endif
 #define MAP_SIZE            (1 << MAP_SIZE_POW2)

 /* Maximum allocator request size (keep well under INT_MAX): */
index e3675d9f8..b287dccb6 100644
--- a/afl_integration/afl-2.52b_kscheduler_large_bitmap/config.h
+++ b/afl_integration/afl-2.52b_kscheduler_large_bitmap/config.h
@@ -315,7 +315,9 @@
    problems with complex programs). You need to recompile the target binary
    after changing this - otherwise, SEGVs may ensue. */

+#if !defined(MAP_SIZE_POW2)
 #define MAP_SIZE_POW2       17
+#endif
 #define MAP_SIZE            (1 << MAP_SIZE_POW2)

 /* Maximum allocator request size (keep well under INT_MAX): */
EOF
