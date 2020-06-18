---
title: Home
---

# Magma: A Ground-Truth Fuzzing Benchmark

Magma is a collection of open-source libraries with widespread usage and a long
history of security-critical bugs and vulnerabilities. In light of the need for
better fuzzer evaluation, we *front-ported* bugs from previous bug reports to
the latest versions of these libraries.

For each ported bug, we added in-line (source-code-level) instrumentation to
collect ground-truth information about bugs **reached** (buggy code executed)
and **triggered** (fault condition satisfied by input). This instrumentation
allows a monitoring utility to measure fuzzer progress in real time.

Magma also includes the `captain` toolset which facilitates the process of
building Magma targets and running campaigns.

## Included Libraries

We selected a handful of diverse targets to include in the initial version of
Magma. These targets were chosen from the Google
[OSS-Fuzz](https://github.com/google/oss-fuzz) list of supported projects which
are actively updated and developed:

1. libpng
1. libtiff
1. libxml2
1. poppler
1. openssl
1. sqlite3
1. php

For each library, we build at least one executable program that consumes an
input file and feeds it to the instrumented library. While these programs are
not guaranteed to maximize library code coverage, they have proven useful as
fuzz targets, since they are used by OSS-Fuzz as libFuzzer/AFL stubs, and a
majority of the reports for front-ported bugs in Magma mention these programs in
the Proof-of-Concept to reproduce the bugs.

## Usage

To use Magma and its scripts, first install the dependencies:
```
apt-get update &&
  apt-get install -y parallel docker.io git
```

Magma uses [GNU Parallel](https://www.gnu.org/software/parallel/) to manage fuzz
campaigns through bash. To silence the citation notice, run either of the
following commands:
```
# Requires user input
parallel --citation

# OR
touch ~/.parallel/will-cite
```

Then clone Magma:
```
git clone --branch v1.0.0 https://github.com/HexHive/magma.git magma
```

From here on, you can use the `captain` scripts (in `tools/captain`) to build,
start, and manage fuzz campaigns.

The `captain/run.sh` script can build fuzzing images and start multiple
campaigns in parallel. To configure it, the `captainrc` file is imported.

For instance, to run a single 24-hour AFL campaign against a Magma target (e.g.,
libpng), the `captainrc` file can be as such:
```
###
## Configuration parameters
###

# WORKDIR: path to directory where shared volumes will be created
WORKDIR=./workdir

# REPEAT: number of campaigns to run per program (per fuzzer)
REPEAT=1

# [WORKERS]: number of worker threads (default: CPU cores)
WORKERS=1

# [TIMEOUT]: time to run each campaign. This variable supports one-letter
# suffixes to indicate duration (s: seconds, m: minutes, h: hours, d: days)
# (default: 1m)
TIMEOUT=24h

# [POLL]: time (in seconds) between polls (default: 5)
POLL=5

# [ISAN]: if set, build the benchmark with ISAN/fatal canaries (default: unset)
ISAN=1

###
## Campaigns to run
###

# FUZZERS: an array of fuzzer names (from magma/fuzzers/*) to evaluate
FUZZERS=(afl)

# [fuzzer_TARGETS]: an array of target names (from magma/targets/*) to fuzz with
# `fuzzer` (default: all targets)
afl_TARGETS=(libpng)
```

Then, execute `./run.sh` in the same directory. The `workdir/log` directory
contains the build and run logs of the campaign. In addition, the fuzzer logs
and outputs can be found in `workdir/findings`.

The collected Magma instrumentation can be found in name-timestamped files
inside `workdir/monitor`. Timestamps are recorded in seconds since the beginning
of the campaign. The contents of each monitor file are a CSV header and data row
representing the global campaign bug reached and triggered counters at that
timestamp. For instance, the `workdir/monitor/43200` file could have the
following contents:
```
AAH001_R, AAH001_T, AAH007_R, AAH007_T
1245, 342, 45324, 6345
```

This indicates that, up until the 12-hour mark, the `AAH001` bug was reached
*1245* times, and triggered *342* times, whereas the `AAH007` bug was reach
*45324* times, and triggered *6345* times.


## Manual Builds

The `captain` toolset also provides scripts to manually build and start
unmanaged campaigns:
```
cd tools/captain

# Build the docker image for AFL and a Magma target (e.g., libpng)
FUZZER=afl TARGET=libpng ./build.sh

# To start a single 24-hour fuzzing campaign, use the start.sh script
mkdir -p ./workdir
FUZZER=afl TARGET=libpng PROGRAM=libpng_read_fuzzer SHARED=./workdir POLL=5 \
  TIMEOUT=24h ./start.sh
```

## Magma Versioning

To guarantee replicatable results across evaluations, Magma uses semantic
versioning:

1. *MAJOR*: A Magma release with incompatible API/toolset changes
1. *MINOR*: An update to Magma that modifies targets (e.g., updates version or
   ref) or patches (e.g., adds/removes bugs), making evaluations not comparable
   across minor releases.
1. *PATCH*: An update or a hotfix to the toolset or build system in a
   backward-compatible manner that preserves benchmark results.

The first stable and anchored release of Magma is `v1.0.0`.

## TODOs

Magma is being continuously updated to add support for more fuzzing methods and
applications. To that end, the near-future list of TODOs is the following:

1. Add better instrumentation to collect information about bug distribution and
   complexity.
1. Add more bugs and libraries.
1. ~~Add support for in-process fuzzers through stub functions.~~
1. ~~Improve collection method for canary statistics. Currently, bug ID is the
   index of the bug counters in a fixed-size shared-memory array, and the size
   of the array is hard-coded and needs to be manually updated as more bugs are
   added.~~

The long-term milestones of this project are:

1. Implement an introspective system for collecting bug information, instead of
   in-line canaries.
1. Set up an online continuous evaluation platform with live statistics for
   different fuzzers (à la oss-fuzz).
1. Investigate seed selection methods for better seed coverage.
1. Investigate binaries that maximize library coverage (à la FuzzGen).
1. Add support for multithreaded libraries and make instrumentation thread-safe.
1. ~~Revamp the build system to make it more efficient. Currently, it could result
   in work being duplicated, like compiling the benchmark twice with the same
   compiler configuration or compiling all libraries twice just to change the
   MAGMA_STORAGE value (which only affects one object file).~~
