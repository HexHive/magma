---
title: Home
---

# Magma: A Ground-Truth Fuzzing Benchmark

Magma is a collection of open-source libraries with widespread usage and a long
history of security-critical bugs and vulnerabilities. In light of the need for
better fuzzer evaluation, we front-ported bugs from previous bug reports to the
latest versions of these libraries, which are constantly being updated with new
patches and features, possibly introducing even more undiscovered bugs. This
last fact allows us to continuously update Magma with new bugs as they are
reported, instead of using old stale versions of the libraries.

For each ported bug, we added in-line (source-code-level) instrumentation to
collect ground-truth information about bugs reached (buggy code executed) and
triggered (fault condition satisfied by input). This instrumentation allows a
monitoring utility to measure fuzzer progress in real time.

## Included Libraries

So far, we have added the following libraries to Magma:

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
fuzz targets, since a majority of the reports for front-ported bugs in Magma
mention that these programs can be used to trigger the bugs.

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

## Usage

To use Magma and its scripts, first install the dependencies:
```
apt-get update &&
  apt-get install -y screen parallel docker.io git snapd
snap install yq
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
git clone https://github.com/HexHive/magma.git magma
```

From here on, you can use the Captain scripts (in `tools/captain`) to build,
start, and manage fuzz campaigns.

For instance, to run a single AFL campaign against a Magma target, follow these
steps:
```
cd tools/captain

# Build the docker image for AFL and a Magma target (e.g., libpng)
FUZZER=afl TARGET=libpng ./build.sh

# To start a single 24-hour fuzzing campaign, use the start.sh script
mkdir -p ./workdir
FUZZER=afl TARGET=libpng PROGRAM=libpng_read_fuzzer SHARED=./workdir POLL=5 \
  TIMEOUT=24h ./start.sh
```

To **build and run** a set of campaigns against multiple targets, the Captain
toolset includes a script to manage these campaigns:
```
mkdir -p ./workdir
cat > ./config.yaml << EOF
afl:
  - libpng
  - libtiff
aflfast:
  - libxml2
  - poppler
EOF

# define MAGMA_CACHE_ON_DISK to use disk-backed storage while the campaign is
#   running, instead of a tmpfs volume.
WORKDIR=./workdir REPEAT=5 WORKERS=6 TIMEOUT=24h POLL=5 MAGMA_CACHE_ON_DISK=1 \
  ./run.sh
```
