//===- afl_driver.cpp - a glue between AFL and libFuzzer --------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

/* This file allows to fuzz libFuzzer-style target functions
 (LLVMFuzzerTestOneInput) with AFL using AFL's persistent (in-process) mode.

Usage:
################################################################################
cat << EOF > test_fuzzer.cc
#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 0 && data[0] == 'H')
    if (size > 1 && data[1] == 'I')
       if (size > 2 && data[2] == '!')
       __builtin_trap();
  return 0;
}
EOF
# Build your target with -fsanitize-coverage=trace-pc-guard using fresh clang.
clang -g -fsanitize-coverage=trace-pc-guard test_fuzzer.cc -c
# Build afl-llvm-rt.o.c from the AFL distribution.
clang -c -w $AFL_HOME/llvm_mode/afl-llvm-rt.o.c
# Build this file, link it with afl-llvm-rt.o.o and the target code.
clang++ afl_driver.cpp test_fuzzer.o afl-llvm-rt.o.o
# Run AFL:
rm -rf IN OUT; mkdir IN OUT; echo z > IN/z;
$AFL_HOME/afl-fuzz -i IN -o OUT ./a.out
################################################################################
AFL_DRIVER_STDERR_DUPLICATE_FILENAME: Setting this *appends* stderr to the file
specified. If the file does not exist, it is created. This is useful for getting
stack traces (when using ASAN for example) or original error messages on hard
to reproduce bugs. Note that any content written to stderr will be written to
this file instead of stderr's usual location.

AFL_DRIVER_CLOSE_FD_MASK: Similar to libFuzzer's -close_fd_mask behavior option.
If 1, close stdout at startup. If 2 close stderr; if 3 close both.

*/
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <vector>

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
extern "C" {
__attribute__((weak))
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
  // does nothing
  assert(false && "LLVMFuzzerTestOneInput should not be called from afl_driver");
  return 0;
}
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
}

// Input buffer.
static const size_t kMaxAflInputSize = 1 << 20;
static uint8_t AflInputBuf[kMaxAflInputSize];

// Keep track of where stderr content is being written to, so that
// dup_and_close_stderr can use the correct one.
static FILE *output_file = stderr;

static void Printf(const char *Fmt, ...) {
  va_list ap;
  va_start(ap, Fmt);
  vfprintf(output_file, Fmt, ap);
  va_end(ap);
  fflush(output_file);
}

// Define LLVMFuzzerMutate to avoid link failures for targets that use it
// with libFuzzer's LLVMFuzzerCustomMutator.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  assert(false && "LLVMFuzzerMutate should not be called from afl_driver");
  return 0;
}

// Execute any files provided as parameters.
static int ExecuteFilesOnyByOne(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    std::ifstream in(argv[i], std::ios::binary);
    in.seekg(0, in.end);
    size_t length = in.tellg();
    in.seekg (0, in.beg);
    if (length < 0 || length > kMaxAflInputSize) {
      continue;
    }
    // Allocate exactly length bytes so that we reliably catch buffer overflows.
    std::vector<char> bytes(length);
    in.read(bytes.data(), bytes.size());
    assert(in);
    LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(bytes.data()),
                           bytes.size());
  }
  return 0;
}

__attribute__((weak))
int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  // Do any other expensive one-time initialization here.

  if (argc > 1)
    return ExecuteFilesOnyByOne(argc, argv);

  ssize_t n_read = read(0, AflInputBuf, kMaxAflInputSize);
  if (n_read > 0) {
    // Copy AflInputBuf into a separate buffer to let asan find buffer
    // overflows. Don't use unique_ptr/etc to avoid extra dependencies.
    uint8_t *copy = new uint8_t[n_read];
    memcpy(copy, AflInputBuf, n_read);
    LLVMFuzzerTestOneInput(copy, n_read);
    delete[] copy;
  }
}