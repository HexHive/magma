# Using Magma

After building the Magma binaries, and in order to collect information about
fuzzer progress, a monitoring utility must be first launched before executing
the instrumented binaries.

In its current implementation, Magma uses POSIX shared memory objects to store
persistent information. To read it, a monitoring utility must open the shmem
object, whose name was specified during build in `MAGMA_STORAGE`. The size of
the shmem object and the format of data in it is specified in the `magma`
library in the `codebase`, specifically, in `canary.h` and `canary.c`.

Magma ships with two utilities that function as monitoring utilities. For every
build, Magma's build system generates a `monitor` binary in `build` which sets
up the shmem object and prints its contents. To delete the shmem object, launch
monitor as `./monitor --rm`. The `monitor` utility is convenient for quickly
checking if the canaries are working as expected or if some manual program input
reaches/triggers some bug.

The other monitor is included in the `benchd` toolset which is designed for
launching long-running campaigns and collecting and processing fuzzer progress
information.

The `benchd` toolset manages fuzzing campaigns, runs multiple campaigns
concurrently for a specified time duration, and collects and saves canary
information. The provided scripts, `logparse.py` and `postproc.py` also help in
parsing and processing monitor logs and fuzzer findings. Look at the `--help`
output of these scripts to determine usage.

Don't forget to set up the environment for the fuzzers under test. AFL and Angora, for instance, requires the following:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
sudo bash -c 'cd /sys/devices/system/cpu; echo performance | tee cpu*/cpufreq/scaling_governor'
```
