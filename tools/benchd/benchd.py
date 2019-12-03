#!/usr/bin/env python3

import os
from fuzzers import AFLFuzzer, AFLFastFuzzer, MOptAFLFuzzer, FairFuzzFuzzer, \
    AngoraFuzzer, honggfuzzFuzzer, AFLGoFuzzer
from fuzzer import FuzzerBenchmark, Scheduler
from config import *

BENCHD_OUTDIR = "/root/campaigns"

BENCHD_FUZZERS = {
    "afl": {
        "instance": AFLFuzzer("/root/fuzzers/afl/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "afl"),
        "exclude_targets": [],
        "env": {}
    },
    "aflfast": {
        "instance": AFLFastFuzzer("/root/fuzzers/aflfast/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "aflfast"),
        "exclude_targets": [],
        "env": {}
    },
    "moptafl": {
        "instance": MOptAFLFuzzer("/root/fuzzers/moptafl/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "moptafl"),
        "exclude_targets": [],
        "env": {}
    },
    "fairfuzz": {
        "instance": FairFuzzFuzzer("/root/fuzzers/fairfuzz/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "fairfuzz"),
        "exclude_targets": [],
        "env": {}
    },
    "angora": {
        "instance": AngoraFuzzer("/root/fuzzers/angora/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "angora"),
        "exclude_targets": ["poppler"],
        "env": {
            "ANGORA_TAINT_RULE_LIST": os.path.join(MAGMA_DIR, "rules/abi.txt")
        }
    },
    "honggfuzz": {
        "instance": honggfuzzFuzzer("/root/fuzzers/honggfuzz/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "honggfuzz"),
        "exclude_targets": [],
        "env": {
            "HFUZZ_CC_USE_GCC_BELOW_8": "1"
        }
    },
    "aflgo": {
        "instance": AFLGoFuzzer("/root/fuzzers/aflgo/"),
        "workdir": os.path.join(BENCHD_OUTDIR, "aflgo"),
        "exclude_targets": [],
        "env": {}
    }
}

def main():
    trials = 5
    timeout = 3600 * 24
    threads = 12

    sch = Scheduler(threads)
    for fuzzer in BENCHD_FUZZERS.values():
        sch.add_benchmark(
            FuzzerBenchmark(
                fuzzer["instance"], fuzzer["workdir"],
                trials=trials, timeout=timeout, fatal=True,
                exclude_targets=fuzzer["exclude_targets"],
                **fuzzer["env"]
            )
        )

    sch.start()

if __name__ == '__main__':
    main()
