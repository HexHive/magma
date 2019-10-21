import os
from fuzzers import AFLFuzzer, AFLFastFuzzer, MOptAFLFuzzer, FairFuzzFuzzer, AngoraFuzzer, honggfuzzFuzzer
from fuzzer import FuzzerBenchmark, Scheduler, MAGMA_DIR

def main():
    trials = 5
    timeout = 3600 * 24
    threads = 12

    out_dir = "/root/campaigns"

    afl = AFLFuzzer("/root/fuzzers/afl/")
    afl_bm = FuzzerBenchmark(afl, os.path.join(out_dir, "afl"), trials=trials, timeout=timeout, fatal=True)

    aflfast = AFLFastFuzzer("/root/fuzzers/aflfast/")
    aflfast_bm = FuzzerBenchmark(aflfast, os.path.join(out_dir, "aflfast"), trials=trials, timeout=timeout, fatal=True)
    
    moptafl = MOptAFLFuzzer("/root/fuzzers/moptafl/")
    moptafl_bm = FuzzerBenchmark(moptafl, os.path.join(out_dir, "moptafl"), trials=trials, timeout=timeout, fatal=True)
    
    fairfuzz = FairFuzzFuzzer("/root/fuzzers/fairfuzz/")
    fairfuzz_bm = FuzzerBenchmark(fairfuzz, os.path.join(out_dir, "fairfuzz"), trials=trials, timeout=timeout, fatal=True)

    angora = AngoraFuzzer("/root/fuzzers/angora/")
    angora_bm = FuzzerBenchmark(angora, os.path.join(out_dir, "angora"), trials=trials, timeout=timeout, fatal=True, exclude_targets=["poppler"], ANGORA_TAINT_RULE_LIST=os.path.join(MAGMA_DIR, "rules/abi.txt"))

    honggfuzz = honggfuzzFuzzer("/root/fuzzers/honggfuzz")
    honggfuzz_bm = FuzzerBenchmark(honggfuzz, os.path.join(out_dir, "honggfuzz"), trials=trials, timeout=timeout, fatal=True)

    sch = Scheduler(threads)
    sch.add_benchmark(afl_bm)
    sch.add_benchmark(aflfast_bm)
    sch.add_benchmark(moptafl_bm)
    sch.add_benchmark(fairfuzz_bm)
    sch.add_benchmark(angora_bm)
    sch.add_benchmark(honggfuzz_bm)
    sch.start()

if __name__ == '__main__':
    main()
