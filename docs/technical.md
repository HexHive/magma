---
title: Technical Reference
---

## Overview

In addition to being a collection of real targets with ground-truth bugs, Magma
also provides an infrastructure of build scripts and toolsets that facilitate
the usage of the benchmark and make it usable out-of-the-box. To achieve that,
Magma relies on the Docker build system and provides a Dockerfile that specifies
the build process.

## Docker Images

To enable the quick launching of experiments and identical campaigns, Magma
relies on Docker images that set up the fuzzing environment and allow running
multiple identical and independent campaigns concurrently.

A fuzzing environment is mainly identified by the *fuzzer* and the *target*,
alongside the *program* and the *args* used when launching the program. The
other parameters listed in `captainrc` also factor into the fuzzing environment,
but variations of them cannot co-exist in the same *fuzzer/target*
configuration.

As such, every built image is identified by the tag `magma/fuzzer/target`. Each
images contains all the support files needed for compiling and running the
fuzzer and instrumenting the target (if needed) using the fuzzer's own compiler.

Launching a campaign then simply becomes a matter of specifying which _program_
to launch when running a container based on that image, as well as what
command-line _args_ to use. Targets (libraries) can have multiple programs that
execute different parts of the code base, and allowing the flexibility to fuzz
different programs is key to Magma's operation.

Magma provides multiple programs as execution drivers for fuzzing. However, in a
similar manner to seed files, a fuzzer could the provided execution drivers as a
"hint" for how to fuzz the target, possibly using generated execution drivers
(e.g., FuzzGen).

### Dockerfile

The Magma Dockerfile defines the build process for the Docker images, and its
instructions are ordered in a manner that increases cache re-usability across
builds.

The Dockerfile accepts the following build arguments:

|Build Arg.           |Description                                                                                                         |
|---------------------|--------------------------------------------------------------------------------------------------------------------|
|`fuzzer_name`        |the name of the fuzzer, as listed in `magma/fuzzers`                                                                |
|`target_name`        |the name of the target, as listed in `magma/targets`                                                                |
|`USER_ID`, `GROUP_ID`|the user and group ID of the `magma` user inside the image (should match external uid/gid when using shared volumes)|
|`canaries`           |if set, specifies that canaries must be enabled                                                                     |
|`fixes`              |if set, specifies that fixes must be enabled (bugs disabled)                                                        |
|`isan`               |if set, specifies that the IdealSanitization mode is used                                                           |
|`harden`             |if set, specifies that instrumentation storage must be `mprotect()`'d                                               |

Beyond that, the Dockerfile specifies the order of building the fuzzing
environment:
1. `{magma, fuzzer, target}/preinstall.sh`: installs the dependencies **(runs as
   `root`)**
1. `magma/prebuild.sh`: builds the Magma monitoring utility with an
   un-instrumented compiler (`gcc`/`g++`)
1. `fuzzer/{fetch, build}.sh`: retrieves the fuzzer code and builds it
1. `target/fetch.sh`: retrieves the target code
1. `magma/apply_patches.sh`: instruments the target with in-line canaries
1. `fuzzer/instrument.sh`: builds the target as defined by the fuzzer's build
   configuration (e.g., custom compiler, multiple binaries, etc...)

Finally, the entry point is specified to be Magma's `magma/run.sh` script which
launches the monitoring utility in parallel with the fuzzer.

### Environment Variables

The Dockerfile creates the following directories and assigns their values to
environment variables:

|Env. Var. |Value          |Description                                                                                                       |
|----------|---------------|------------------------------------------------------------------------------------------------------------------|
|`$MAGMA_R`|`/magma/`      |The directory which stores the needed configuration files (`magma`, `fuzzers/my_fuzzer`, `targets/my_target`).    |
|`$SHARED` |`/magma_shared`|The path where the shared volume with the host is mounted. It contains fuzzer findings, logs, and monitor outputs.|
|`$OUT`    |`/magma_out`   |The directory where compiled programs are stored. Every target build script must copy its output binaries here.   |

Additionally, the Dockerfile also exports the following environment variables:

|Env. Var.                  |Value             |Description                                                                 |
|---------------------------|------------------|----------------------------------------------------------------------------|
|`$MAGMA`                   |`/magma/magma`    |The path to the directory with Magma's support files inside the container.  |
|`$FUZZER`                  |`/magma/my_fuzzer`|The path to the fuzzer's configuration directory inside the container.      |
|`$TARGET`                  |`/magma/my_target`|The path to the target's configuration directory inside the container.      |
|`${C,CXX,LD}FLAGS`, `$LIBS`|*Check Dockerfile*|Initial compiler and linker flags needed to support Magma's instrumentation.|

Finally, the following environment variables must be assigned when running a
Magma Docker container:

|Env. Var. |Description                                                                      |
|----------|---------------------------------------------------------------------------------|
|`PROGRAM` |the name of the compiled program executable                                      |
|`ARGS`    |an AFL-style string of command-line arguments                                    |
|`POLL`    |the poll duration, in seconds, as defined in `captainrc`                         |
|`TIMEOUT` |the campaign duration, as defined in `captainrc`                                 |
|`AFFINITY`|a comma-separated list of logical CPU cores which are allocated for this campaign|

Those environment variables can be provided to the container through the
command-line argument `-e NAME=VALUE` when using `docker-run` or
`docker-create`.

## Fuzzer Configuration

Inside the container, the `$FUZZER` directory stores the scripts needed to build
the fuzzer and compile the targets.

|File Name      |Description                                                                                                                                                                |
|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`preinstall.sh`|Installs the fuzzer's dependencies. Must be run as `root`.                                                                                                                 |
|`fetch.sh`     |Retrieves the source code for building the fuzzer. Typically stores it in `$FUZZER/repo`.                                                                                  |
|`build.sh`     |Compiles the fuzzer binaries and support files (e.g., the `afl_driver.cpp` used to wrap libFuzzer stubs).                                                                  |
|`instrument.sh`|Compiles the target, performing any required pre-processing or adding fuzzer-specific instrumentation.                                                                     |
|`runonce.sh`   |Runs the `$OUT/$PROGRAM` executable against the first argument (`$1`), simulating the conditions of the fuzzer's runtime environment (e.g., memory limit, timeout, etc...).|
|`run.sh`       |Launches the fuzzing campaign, reading seed files from `$TARGET/corpus/$PROGRAM/` and writing results to `$SHARED/findings`.                                               |
|`findings.sh`  |Outputs a newline-separated list of pathnames to the fuzzer-generated test-cases.                                                                                          |

## Target Configuration

Inside the container, the `$TARGET` directory stores the scripts needed to build
the target.

|File Name      |Description                                                                                                           |
|---------------|----------------------------------------------------------------------------------------------------------------------|
|`preinstall.sh`|Installs the target's dependencies. Must be run as `root`.                                                            |
|`fetch.sh`     |Retrieves the source code for building the target. It **must** store it in `$FUZZER/repo`.                            |
|`build.sh`     |Compiles the target binaries, making use of `${C,CXX,LD}FLAGS` and `$LIBS`, and stores the program binaries in `$OUT`.|

In addition, the `configrc` file in this directory specifies the valid
`$PROGRAM` and `$ARGS` values. A sample `configrc` is listed here:

```
PROGRAMS=(pdf_fuzzer pdfimages pdftoppm)

pdfimages_ARGS="@@ /tmp/out"
pdftoppm_ARGS="-mono -cropbox @@"
```

This directory must also include the following subdirectories:
* `corpus/$PROGRAM/`: for every `$PROGRAM`, a corpus of seed files must be
  available at runtime (either provided as part of the configuration, or
  generated in the target `build.sh` script at compile-time).
* `patches/setup/`: contains a set of patch files that prepare the target to be
  compiled with Magma.
* `patches/bugs/`: contains a set of patch files that forward-port bugs and
  instrument the program with ground-truth canaries. Other subdirectories, like
  `patches/graveyard/`, can be added, but will only be used for book-keeping.

## Magma Support Files

Inside the container, the `$MAGMA` directory stores the scripts needed to build
Magma and prepare its targets.

### Build and Run Scripts

Just under the `$MAGMA` directory, the following scripts are stored:

|File Name         |Description                                                                                                                                       |
|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
|`preinstall.sh`   |Installs Magma's dependencies. Must be run as `root`.                                                                                             |
|`prebuild.sh`     |Builds the Magma `monitor` using the default un-instrumented compiler (vanilla GCC/Clang).                                                        |
|`build.sh`        |Compiles the Magma runtime library, `$OUT/magma.o`, needed for compiling and running the instrumentation.                                         |
|`apply_patches.sh`|Applies the patch files stored in `$TARGET/patches/bugs/` to the code base in `$TARGET/repo/`.                                                    |
|`runonce.sh`      |Runs the `$OUT/$PROGRAM` executable against the first argument (`$1`). Returns zero if no bugs or crashes are encountered, and non-zero otherwise.|
|`run.sh`          |Prunes the `$TARGET/corpus/$PROGRAM/` directory for faulty seeds, starts the monitor, and launches the campaign.                                  |

### Instrumentation

The `$MAGMA/src` directory contains the support files needed to compile the
Magma runtime, mainly support for canaries.

The `canary.c` file defines the three main functions used in Magma:

|Function Name  |Description                                                                                                                              |
|---------------|-----------------------------------------------------------------------------------------------------------------------------------------|
|`magma_init`   |Initializes the `mmap()`'d region used as storage for the global instrumentation statistics.                                             |
|`magma_protect`|Toggles the storage page's permissions between read-only and read-writable to protect the region from rogue overwrites.                  |
|`magma_log`    |Logs the call to the canary. After the first occurrence of `condition == true`, `magma_faulty` is set, and no future canaries are logged.|

`magma_protect()` is only called when `MAGMA_HARDEN_CANARIES` is defined at
compile-time, by setting the `HARDEN` parameter in `captainrc`.

The `MODE=1` parameter in `captainrc` defines the compile-time macro
`MAGMA_ENABLE_CANARIES`, which inserts calls to `magma_log()` at bug locations.
However, some custom fuzzer configuration may require instrumentation to be
disabled (e.g., a fuzzer that compiles two versions of the target, one for
fuzzing and another for analysis). In that case, the fuzzer can define the
`MAGMA_DISABLE_CANARIES` macro, which maintains the calls to `magma_log()`, but
makes it behave like a `NOP`.

When calling `magma_log()`, the `condition` must be constructed using the
`MAGMA_AND` and `MAGMA_OR` macros (which are aliases for the `magma_and` and
`magma_or` functions). These functions are written in such a way to minimize
information leakage through some fuzzer-specific coverage instrumentation. The
`arch/` subdirectory contains the different implementations of these functions
depending on the build architecture. Custom implementations could be added as a
separate architecture, and then enabled by `#include`-ing the definition file in
`canary.h`.

The instrumentation implements a simple one-slot single-producer single-consumer
storage component that allows the `monitor` to constantly pull the latest
results from the storage region without risk of data races, and without the
overhead and complexity of synchronization.

If `MAGMA_STORAGE` is a defined environment variable at runtime, its value is
used as the path to file to be used as the storage object. Otherwise,
`$SHARED/canaries.raw` is used, as defined in `$MAGMA/build.sh` at compile-time.

The storage component is defined in `storage.c` but is orthogonal to the core
operation of Magma.

### Monitor

The `$MAGMA/src` directory also contains the code for the `monitor` utility,
which is responsible for dumping runtime instrumentation statistics in a
parse-able format.

The utility is invoked as such:
```
monitor [--dump {raw|row|human}] [--fetch {file FILE|watch COMMAND}]
```

The `--dump` argument can take the following values:

|Value  |Description                                                                                                                                                                                                             |
|-------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`raw`  |The raw memory bytes of the storage region. This is the default mode.                                                                                                                                                   |
|`row`  |A CSV-style representation, where the first row defines header names, and the second row records counter values. `BUG_R` and `BUG_T` represent the counters for `BUG` being **reached** and **triggered**, respectively.|
|`human`|Each bug is printed on a separate line with the format: `BUG reached REACHED_COUNT triggered TRIGGERED_COUNT`                                                                                                           |

The `--fetch` argument can take the following values:

|Value  |Description                                                                                                                                                        |
|-------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`file` |Reads the `FILE` as a storage object. This is the default mode.                                                                                                    |
|`watch`|Exports the path to a temporary file as a `MAGMA_STORAGE` environment variable and runs the `COMMAND` to collect instrumentation statistics for a single execution.|

## Captain Toolset: Running the Benchmark

The set of scripts in the `captain` toolset is provided to allow automated
interaction with the Docker build system. Each script defines a set of
*pre-requirements*, which are essentially the launch arguments when running the
script, in the first few lines of comments.

|File Name        |Description                                                                                                                           |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------------|
|`build.sh`       |Builds the Docker image based for the `$FUZZER/$TARGET` configuration.                                                                |
|`start.sh`       |Launches a single fuzzing campaign (useful for testing).                                                                              |
|`extract.sh`     |A post-processing script to extract PoC files from fuzzer-generated test-cases.                                                       |
|`run.sh`         |Launches and manages multiple concurrent campaigns, building any missing images in the process. Requires `captainrc`.                 |
|`post_extract.sh`|Launches the extraction script, in case extraction was not done with `run.sh` (i.e., `POC_EXTRACT` was not set). Requires `captainrc`.|
|`common.sh`      |Initializes a common set of functions and variables. Not to be executed out of context.                                               |

## Benchd Toolset: Processing Results

This toolset is a work-in-progress and its documentation is not entirely stable.

### exp2json.py

Generates the experiment summary and outputs it as a JSON file.

Requirements:
* `pandas >= 1.1.0`

Usage:
```
usage: exp2json.py [-h] [--workers WORKERS] workdir outfile

positional arguments:
  workdir            The path to the Captain tool output workdir.
  outfile            The file to which the output will be written, or - for
                     stdout.

optional arguments:
  -h, --help         show this help message and exit
  --workers WORKERS  The number of concurrent processes to launch.

```

The JSON object has the following format:
```
{
    "FUZZER": {
        "TARGET": {
            "PROGRAM": {
                "RUN": {
                    "reached": {
                        "BUGID": int(TIME_TO_REACH_BUG)
                    },
                    "triggered": {
                        "BUGID": int(TIME_TO_TRIGGER_BUG)
                    }
                },
                "RUN": ...
            },
            "PROGRAM": ...
        },
        "TARGET": ...
    },
    "FUZZER": ...
}
```

`TIME_TO_REACH_BUG` and `TIME_TO_TRIGGER_BUG` are represented in _seconds_, with
a resolution of `POLL` seconds, since the beginning of the experiment.

## Reports Toolset: Visualizing Results

This toolset is a work-in-progress and its documentation will be released when
the scripts are ready to be publicized.