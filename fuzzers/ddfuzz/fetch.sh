#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/elManto/DDFuzz "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 319f702e9a2317970d829e458ec6d035f0aeb134

# Fix: CMake-based build systems fail with duplicate (of main) or undefined references (of LLVMFuzzerTestOneInput)
sed -i '{s/^int main/__attribute__((weak)) &/}' $FUZZER/repo/utils/aflpp_driver/aflpp_driver.c
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' $FUZZER/repo/utils/aflpp_driver/aflpp_driver.c
cat >> $FUZZER/repo/utils/aflpp_driver/aflpp_driver.c << EOF
__attribute__((weak))
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  // assert(0 && "LLVMFuzzerTestOneInput should not be implemented in afl_driver");
  return 0;
}
EOF

patch -p1 -d "$FUZZER/repo" << EOF
--- a/utils/aflpp_driver/aflpp_driver.c
+++ b/utils/aflpp_driver/aflpp_driver.c
@@ -53,7 +53,7 @@
   #include "hash.h"
 #endif

-int                   __afl_sharedmem_fuzzing = 1;
+int                   __afl_sharedmem_fuzzing = 0;
 extern unsigned int * __afl_fuzz_len;
 extern unsigned char *__afl_fuzz_ptr;

@@ -111,7 +111,8 @@ extern unsigned int * __afl_fuzz_len;
 __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

 // Notify AFL about persistent mode.
-static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
+// DISABLED to avoid afl-showmap misbehavior
+static volatile char AFL_PERSISTENT[] = "##SIG_AFL_NOT_PERSISTENT##";
 int                  __afl_persistent_loop(unsigned int);

 // Notify AFL about deferred forkserver.
EOF
