#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AFLplusplus/AFLplusplus "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 5ee63a6e6267e448342ccb28cc8d3c0d34ffc1cd

# Fix: CMake-based build systems fail with duplicate (of main) or undefined references (of LLVMFuzzerTestOneInput)
sed -i '{s/^int main/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.c
sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' $FUZZER/repo/examples/aflpp_driver/aflpp_driver.c
cat >> $FUZZER/repo/examples/aflpp_driver/aflpp_driver.c << EOF
__attribute__((weak))
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  // assert(0 && "LLVMFuzzerTestOneInput should not be implemented in afl_driver");
  return 0;
}
EOF

patch -p1 -d "$FUZZER/repo" << EOF
--- a/examples/aflpp_driver/aflpp_driver.c
+++ b/examples/aflpp_driver/aflpp_driver.c
@@ -111,7 +111,8 @@ extern unsigned int * __afl_fuzz_len;
 __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
 
 // Notify AFL about persistent mode.
-static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
+// DISABLED to avoid afl-showmap misbehavior
+static volatile char AFL_PERSISTENT[] = "##SIG_AFL_NOT_PERSISTENT##";
 int                  __afl_persistent_loop(unsigned int);
 
 // Notify AFL about deferred forkserver.
--- a/src/afl-showmap.c
+++ b/src/afl-showmap.c
@@ -1021,6 +1021,7 @@ int main(int argc, char **argv_orig, char **envp) {
     if (arg_offset && use_argv[arg_offset] != stdin_file) {
 
       use_argv[arg_offset] = strdup(stdin_file);
+      fsrv->out_file = use_argv[arg_offset];
 
     }
EOF
