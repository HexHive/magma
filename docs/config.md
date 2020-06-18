---
title: Configuration
---

## Configuring `run.sh`

The `captainrc` file defines the configuration parameters for the `captain`
toolset scripts, mainly `run.sh`. Each parameter control some aspect of the
benchmarking process (i.e., build-time, run-time, launch configuration, ...).

### `WORKDIR`

It defines the path to the directory in which the current instance of `run.sh`
will store its outputs and transient results. The `WORKDIR` directory has the
following hierarchy:

```
./
|
-- cache: transient storage for currently-running campaigns
|
-- ar: archived campaign results (optionally tar-balled)
|
-- log: docker build-time and run-time logs
|
-- poc: collected test-cases that trigger known bugs or new crashes
```

The `cache` and `ar` subdirectories have the following hierarchy:
```
./
|
-- [FUZZER]
|  |
|  -- [TARGET]
|  |  |
|  |  -- [PROGRAM]
|  |  |  |
|  |  |  -- [RUN]
|  |  ...
|  ...
...
```

Each `[RUN]` directory contains the run-time results of that campaign:

```
./
|
-- findings: the output directory supplied to the fuzzer
|
-- log: the fuzzer's stdout and stderr streams, stored in log/current
|
-- monitor: timestamped files containing instrumentation results
```

### `REPEAT`


It specifies the number of times each experiment must be identically repeated.
Every repetition is assigned a locally-unique `RUN` serial number (0, 1, 2, ...)
in the workdir hierarchy as discussed above.

### `WORKERS`

It defines the maximum number of logical CPU cores to use concurrently.

### `TIMEOUT`

It specifies the duration for which each campaign/repetition must execute for.
The format of the `TIMEOUT` value is that supported by the GNU `coreutils`
`timeout` utility:
* `10s` for 10 seconds
* `20m` for 20 minutes
* `24h` for 24 hours
* `7d` for 7 days

The omission of the letter-suffix defaults to using seconds.

### `POLL`

To avoid synchronization complexity and slow-down, Magma continuously *polls*
the instrumentation storage file and saves its contents in the `monitor`
directory for every `RUN`. This parameter defines how long to wait, in
*seconds*, between subsequent polls.

### `CACHE_ON_DISK`

To speed up the fuzzing process and reduce I/O bottlenecking of the
fuzzer/target/instrumentation, Magma defaults to mounting the `cache` directory
as a `tmpfs` volume. However, this could result in high memory usage, and requires root privileges to mount and unmount the volume.

To disable this behavior, it suffices to *define* (uncomment) this parameter.

### `TMPFS_SIZE`

In case `CACHE_ON_DISK` is not defined, and `tmpfs` is used, this parameter
defines the size of the volume to mount.

The format of the `TMPFS_SIZE` value is that supported by the `mount` utility:
* `10k` for 10 Kibibytes (binary kilo)
* `10m` for 10 Mebibytes (binary mega)
* `10g` for 10 Gibibytes (binary giga)

### `NO_ARCHIVE`

To facilitate the process of moving campaign results, Magma defaults to
tar-balling `RUN` directories before storing them in the `ar` directory.

To disable this behavior, it suffices to *define* (uncomment) this parameter.

### `CANARY_MODE`

Magma's bugs and instrumentation can be configured at build-time in one of three
modes:

1. `1`: Fixes are excluded (bugs are included), and canaries (instrumentation)
   are enabled. This is the default mode.
1. `2`: Fixes are excluded, and canaries are disabled. This is useful to test if
   a fuzzer is over-fitting to canaries, or if the instrumentation is
   introducing new bugs.
1. `3`: Fixes are included (bugs are excluded), and canaries are disabled. This
   is useful to test if a discovered crash is true or a false positive.

### `ISAN`

Magma includes an "ideal sanitization" mode whereby any bug triggered will
immediately cause a crash. This is synonymous with AddressSanitizer's policy to
terminate the program when a memory safety violation is detected.

    Once a memory corruption occurs, the program is in an inconsistent state,
    which could lead to confusing results and potentially misleading subsequent
    reports.

With Magma's ISan, the fuzzer is evaluated only for its ability to reach and
trigger a bug, but not its ability to detect it (e.g., semantic/logical bugs may
not always produce observable faults or crashes).

This behavior is disabled by default. To enable this behavior, it suffices to
*define* (uncomment) this parameter.

### `HARDEN`

In the event that some bug results in memory corruption and goes undetected, it
is undesirable to have the `mmap()`'d instrumentation data corrupted. Magma
includes a *hardened canaries* mode which `mprotect()`'s the instrumentation
storage region with read-only permissions whenever control is outside the
instrumented block.

This behavior is disabled by default. To enable this behavior, it suffices to
*define* (uncomment) this parameter.

### `POC_EXTRACT`

The `captain` toolset includes a script to automatically triage fuzzer-generated
test-cases and test them against Magma's ground-truth. This script can be run as
a post-processing step after the termination of every campaign.

This behavior is disabled by default. To enable this behavior, it suffices to
*define* (uncomment) this parameter.

### `MAGMA`

The `captain` toolset contains scripts and files that are dependent on other
files present in the same directory. For this purpose, the scripts attempt to
find the current directory, store it in a local variable named `MAGMA`, and use
it to reference those files.

In the event that you encounter problems running the `captain` script (e.g.,
using an incompatible version of Bash), you may specify the path to the Magma
repository (`/path/to/magma/`) as the value of this parameter.

### `FUZZERS`

To evaluate a subset of the fuzzers in the `magma/fuzzers` directory, you can
specify a Bash array of the form:

```
FUZZERS=(afl afl_asan aflplusplus honggfuzz)
# or just
FUZZERS=(my_awsome_fuzzer)
```

Each listed fuzzer name must have a configuration directory in `magma/fuzzers`.

### `fuzzer_TARGETS`

To evaluate a specific fuzzer against a subset of the targets in the
`magma/targets` directory, you can specify a Bash array of the form:

```
my_awsome_fuzzer_TARGETS=(libpng sqlite3 openssl)
```

### `fuzzer_target_PROGRAMS`

To evaluate a specific fuzzer against a subset of the target programs listed in
`magma/targets/TARGET/configrc`, you can specify a Bash array of the form:

```
my_awsome_fuzzer_openssl_PROGRAMS=(x509 server)
```

### `fuzzer_target_program_ARGS`

To define specific AFL-style command-line arguments used by a program against a
fuzzer, you can specify a Bash string variable of the form:

```
my_awsome_fuzzer_libtiff_tiffcp_ARGS="@@ tmp.out"
```

## More Information on IdealSanitizer

In order to speed up the fuzzing process, canaries can be configured to use ISan
mode, but only when applicable. It is possible to forego the overhead of runtime
sanitizers (like ASan, MSan, UBSan, etc...) when the fuzzer only relies on the
`SIGSEGV` signal triggered by such sanitizers to detect faulty behavior.
Instead, the canaries themselves could be used as indicators of faulty behavior,
by configuring them to send such a signal when bug trigger conditions are
satisfied.

Thus, by launching the campaigns using ISan, more fuzzer executions can be
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