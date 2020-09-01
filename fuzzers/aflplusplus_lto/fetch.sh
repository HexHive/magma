#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus "$FUZZER/repo"

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
--- a/src/afl-forkserver.c
+++ b/src/afl-forkserver.c
@@ -937,7 +937,7 @@
 
 #endif
 
-  } else {
+  }
 
     s32 fd = fsrv->out_fd;
 
@@ -975,7 +975,7 @@
 
     }
 
-  }
+
 
 }
 
EOF