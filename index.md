---
title: Home
---

# Magma: A Ground-Truth Fuzzing Benchmark

<div class="intro-container">
<div style="width: 100%">
<p>Magma is a collection of open-source libraries with widespread usage and a long
history of security-critical bugs and vulnerabilities. In light of the need for
better fuzzer evaluation, we <em>front-ported</em> bugs from previous bug reports to
the latest versions of these libraries.</p>

<p>For each ported bug, we added in-line (source-code-level) instrumentation to
collect ground-truth information about bugs <strong>reached</strong> (buggy code executed)
and <strong>triggered</strong> (fault condition satisfied by input). This instrumentation
allows a monitoring utility to measure fuzzer progress in real time.</p>

<p>Magma also includes the <code class="language-plaintext highlighter-rouge">captain</code> toolset which facilitates the process of
building Magma targets and running campaigns.</p>

<p>Check out a <a href="{{ '/reports/sample_2/' | relative_url }}">sample Magma report</a>
and read the <a href="https://hexhive.epfl.ch/publications/files/21SIGMETRICS.pdf">paper</a>.
Questions, comments, and feedback are welcome!</p>
</div>
<div class="thumbnail center">
<a href="https://arxiv.org/abs/2009.01120">
<img class="thumbnail" src="{{ '/assets/img/preprint.png' | relative_url }}">
</a>
</div>
</div>

## Citing Magma
```
@article{Hazimeh:2020:Magma,
  author     = {Ahmad Hazimeh and Adrian Herrera and Mathias Payer},
  title      = {Magma: A Ground-Truth Fuzzing Benchmark},
  year       = {2020},
  issue_date = {December 2020},
  publisher  = {Association for Computing Machinery},
  address    = {New York, NY, USA},
  volume     = {4},
  number     = {3},
  url        = {https://doi.org/10.1145/3428334},
  doi        = {10.1145/3428334},
  journal    = {Proc. ACM Meas. Anal. Comput. Syst.},
  month      = dec,
  articleno  = {49},
  numpages   = {29}
}
```

## Overview

<div class="row">
<div class="col s12 l8 offset-l2">
<img src="{{ '/assets/svg/overview.svg' | relative_url }}" class="materialboxed responsive-img" />
</div>
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
