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

For each library, we build at least one executable program that consumes an
input file and feeds it to the instrumented library. While these programs are
not guaranteed to maximize library code coverage, they have proven useful as
fuzz targets, since a majority of the reports for front-ported bugs in Magma
mention that these programs can be used to trigger the bugs.

## TODOs

Magma is being continuously updated to add support for more fuzzing methods and
applications. To that end, the near-future list of TODOs is the following:

1. Add support for in-process fuzzers through stub functions.
1. Add better instrumentation to collect information about bug distribution and
   complexity.
1. Improve collection method for canary statistics. Currently, bug ID is the
   index of the bug counters in a fixed-size shared-memory array, and the size
   of the array is hard-coded and needs to be manually updated as more bugs are
   added.
1. Add more bugs and libraries.
1. Allow poppler to use the buggy versions of libpng and libtiff.
1. Add processor affinity support to the `benchd` toolset.
1. Replace the use of `git apply` with the GNU `patch` utility so that Magma can
   be distributed without a git dependency.

The long-term milestones of this project are:

1. Implement an introspective system for collecting bug information, instead of
   in-line canaries.
1. Set up an online continuous evaluation platform with live statistics for
   different fuzzers (à la oss-fuzz).
1. Investigate seed selection methods for better seed coverage.
1. Investigate binaries that maximize library coverage (à la FuzzGen).
1. Add support for multithreaded libraries and make instrumentation thread-safe.
1. Revamp the build system to make it more efficient. Currently, it could result
   in work being duplicated, like compiling the benchmark twice with the same
   compiler configuration or compiling all libraries twice just to change the
   MAGMA_STORAGE value (which only affects one object file).

## Build

### Using Dockerfile

We provide a Dockerfile which contains all the steps to build Magma on an image
of Ubuntu 18.04 and clone 6 popular fuzzers (AFL, AFLFast, MOpt-AFL, FairFuzz,
honggfuzz, and Angora) in a directory structure which allows you to start
running the benchmark against these fuzzers out-of-the-box.

To build the Dockerfile and run a Docker container:
```
sudo apt install docker.io
cd docker/
docker build -t magma .
docker create -it --cap-add=SYS_PTRACE --name magma_0 magma
docker start magma_0
docker exec -it magma_0 /bin/bash
```

The `benchd.py` tool shipped with Magma references the directory structure of
the Docker image, and can thus be launched directly to start fuzzing campaigns.

### From Source

The following steps have been tested and verified to work out-of-the-box on
Ubuntu 19.04, 18.04 LTS, and 16.04 LTS. We also tested Ubuntu 14.04 LTS, but
the Ubuntu Trusty package repository has some missing or outdated dependencies;
steps to build Magma on such platforms are not outlined in this README.

To build Magma, the following dependencies must first be installed:
```
git
make
build-essential
cmake >=3.1.0
autoconf >=2.69-9
automake >=1.15.1
libtool
pkgconf
zlib1g-dev
liblzma-dev
libfreetype6-dev
libfontconfig1-dev
libjpeg-dev
libopenjp2-7-dev
python-dev
```

On Debian-based systems, after making sure the required versions are provided by
your package repositories, copy and run the following command:
```
sudo apt install git make build-essential cmake autoconf automake \
    libtool pkgconf \
    zlib1g-dev liblzma-dev libfreetype6-dev libfontconfig1-dev \
    libjpeg-dev libopenjp2-7-dev python-dev
```

It suffices to get a shallow clone of Magma and its submodules:
```
git clone --depth 1 --recurse-submodules https://github.com/HexHive/magma.git
```

Then, to build all of Magma, just run `make all`.

### Custom Compilers and Flags

The provided build system supports the use of custom compilers, by specifying
the environment variables `CC` and `CXX`. Additionally, compiler flags can be
customized by exporting the variables `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, and
`LIBS`.

The `HOST` environment variable can also be set to specify the target build
architecture. Currently, only `x86` and `x86_64` have been tested.

### Magma Build Flags

Magma also supports a handful of flags to customize the canary configuration and
behavior. The following environment variables control these configurations:

* `MAGMA_STORAGE`: the name of the shared memory object where canary statistics
  will be stored. It is recommended to use a unique name for every launched
  campaign, to avoid data races on the same shmem object.
* `MAGMA_SUFFIX`: a string suffix to add to the programs' names in the build dir
  to use as an identifier if needed.
* `MAGMA_ISAN`: if defined, the Ideal Sanitization mode will be used for the
  canaries. Whenever a bug is triggered, the canary will send a SIGSEGV signal
  to the target, causing it to crash.
* `MAGMA_HARDEN`: if defined, canaries will be hardened. In hardened mode, the
  access to shared memory is surrounded by a couple calls to `mprotect`, which
  first set the shmem object's page's permissions to `RW`, allowing the canary
  to report, and then set the permissions back to `R`. This way, an OOB memory
  write during the program execution would not overwrite campaign results.

## Usage

Since Magma currently uses shared memory objects to extract and collect canary
statistics, a monitoring utility must be running to create the shared memory
region. This can be achieved either by running the simplified `monitor` in
`build/`, which just creates the shmem object and prints its formatted contents,
or by running the `monitor.py` script in `tools/benchd/` which logs periodic
real-time statistics into a log file.

Then, the instrumented programs can be launched by fuzzers that allow their
targets to access shared memory directly. Most gray-box fuzzers are thus
compatible, since they rely on concrete execution. White-box fuzzers which rely
symbolic execution tend to emulate the environment and system calls, which
results in a closed system from which the monitoring utility cannot directly
extract canary statistics.

### ISAN

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

### Docker

The provided Dockerfile allows you to directly start running the benchmark
against the deployed fuzzers by just running `python3 benchd.py` in the
`tools/benchd/` directory.

Results will be saved in `/root/campaigns`, and the `logparse.py` and
`postproc.py` scripts can be used to extract meaningful data from the fuzzer
findings and monitor logs.

## Known Issues

* poppler does not compile in x86-32 with the current build system.
* In order to run honggfuzz in Docker, the `SYS_PTRACE` capability must be added
  to the container at creation.