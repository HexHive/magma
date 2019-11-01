# Building Magma

Magma's build system relies on the individual build systems of each of the
included repositories by launching their automake, make, or cmake scripts. As
such, and to reduce the complexity of Magma's build scripts, its build system
does not support incremental building, but rather performs a complete re-build
of the libraries whenever Magma's Makefile is invoked.

Additionally, Magma applies setup and bug patches to the codebase, to add Magma
support to the libraries' build systems, and to forward-port bugs. For that
reason, the `codebase` is copied into a `tmp` directory first, then patches are
applied, and finally, the codebase and supporting files are built in `tmp`, and
the Magma-relevant binaries are copied to `build`.

Build configurations are specified as environment variables and propagated to
the included libraries' build systems. The relevant build configuration
parameters are `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, and `LIBS`.

Additionally, Magma-specific build parameters are also read from the environment
as follows:

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

Magma is built using the Makefile in its root directory. The default build
recipe, `make all`, applies all patches and builds all targets.

To build some targets with specific patches:
```bash
make <xxx.patch <xxy.patch <xxz.patch ...>>> <target <target <target ...>>>
```

The available patches are all the files under the `patches` directory, in
addition to `all_patches`, which applies all the included patches. The available
targets are the names of the directories in the `codebase`, in addition to
`all_targets`, which builds everything.

Thus, the following bash script template covers all the configurable Magma build
system parameters:

```bash
#!/bin/bash
export CC="<path/to/cc>"
export CXX="<path/to/cxx>"
export CFLAGS="<additional C compiler flags>"
export CXXFLAGS="<additional CXX compiler flags>"
export LDFLAGS="<additional LD flags>"
export LIBS="<additional libs to link, e.g.: -lm or -l:path/to/lib>"
export MAGMA_STORAGE="<name of shmem object, e.g., MAGMA_TMP>"
export MAGMA_SUFFIX="<suffix to append, if any>"

# The value of the following env variables is not relevant, as long as they're
# exported.
export MAGMA_ISAN=1
export MAGMA_HARDEN=1

make <xxx.patch <xxy.patch <xxz.patch ...>>> <target <target <target ...>>>
```

To add a new library to the build system, it suffices to modify the `Makefile`
in `codebase` to add a new build recipe named as the library's directory name in
`codebase`. The recipe must configure and invoke the build system of the target
library, and copy the relevant binaries to `$(BINDIR)/programs/`, with the
`MAGMA_SUFFIX` appended to the programs' names.

The binaries eventually copied to `build` contain the required Magma
instrumentation and can be fed into the fuzzers under test.