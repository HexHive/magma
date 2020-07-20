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

Check out a sample Magma report [here]({{ "/reports/sample/" | relative_url }}).

## Overview

<div class="center">
<img src="{{ "/assets/svg/overview.svg" | relative_url }}" class="overview" />
</div>

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
