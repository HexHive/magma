---
title: Configuration
---

## Magma Build Flags

Magma supports a couple of flags to customize the canary configuration and
behavior:

* `MAGMA_ISAN`: the Ideal Sanitization (ISAN) mode will be used for the
  canaries. Whenever a bug is triggered, the canary will send a SIGSEGV signal
  to the target, causing it to crash.
* `MAGMA_HARDEN`: canaries will be hardened. In hardened mode, the access to
  shared memory is surrounded by a couple calls to `mprotect`, which first set
  the shmem object's page's permissions to `RW`, allowing the canary to report,
  and then set the permissions back to `R`. This way, an OOB memory write during
  the program execution would not overwrite campaign results.

For the moment, these are not configurable through a command-line argument or
environment variable, but can be enabled by modifying CFLAGS in the Dockerfile
and defining the macros `MAGMA_FATAL_CANARIES` and `MAGMA_HARDEN_CANARIES`.

## ISAN

In order to speed up the fuzzing process, canaries can be configured to use ISAN
mode, but only when applicable. It is possible to forego the overhead of runtime
sanitizers (like ASan, MSan, UBSan, etc...) when the fuzzer only relies on the
`SIGSEGV` signal triggered by such sanitizers to detect faulty behavior.
Instead, the canaries themselves could be used as indicators of faulty behavior,
by configuring them to send such a signal when bug trigger conditions are
satisfied.

Thus, by launching the campaigns using ISAN, more fuzzer executions can be
performed within the same time duration, allowing you to collect information
about bugs **Reached** and **Triggered**. To collect statistics about bugs
**Detected**, it would then suffice, in a post-processing step, to recompile the
benchmark binaries with the sanitizer of choice and launch the target program
with the fuzzer's reported crashing inputs, listening for any
sanitizer-triggered crashes.

Even though sanitizer crashes are the main fault symptoms, most fuzzers also
configure a time limit and a memory limit, beyond which the program execution is
considered faulty. It is then important to consider those as other forms of
fault detection employed by the fuzzer and measure them during the
post-processing step to make sure that no "crashing" (faulty) cases are
misidentified.