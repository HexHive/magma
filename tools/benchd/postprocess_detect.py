import os
from fuzzers import AFLFuzzer, AFLFastFuzzer, MOptAFLFuzzer, FairFuzzFuzzer, AngoraFuzzer, honggfuzzFuzzer
from fuzzer import MAGMA_LENGTH, MAGMA_DIR
from shutil import copyfile
import subprocess
import monitor
import ctypes
from collections import defaultdict as dd

def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]

out_dir = "/root/campaigns"

fuzzers = {}
for root, dirs, files in walklevel(out_dir, level=1):
    if not bool(fuzzers):
        fuzzers = fuzzers.fromkeys(dirs)
        continue

    f = os.path.basename(root)
    campaigns = [dir.split('_') for dir in dirs]
    campaigns = [
        {
            "fuzzer": c[0],
            "target": c[1],
            "program": c[2],
            "run": c[3],
            "cid": c[4]
        } for c in campaigns]

    targets = set(c["target"] for c in campaigns)
    fuzzers[f] = dict.fromkeys(targets)
    for t in fuzzers[f]:
        fuzzers[f][t] = dict.fromkeys(set(c["program"] for c in campaigns if c["target"] == t))
        for p in fuzzers[f][t]:
            fuzzers[f][t][p] = dict.fromkeys(set(c["run"] for c in campaigns if c["target"] == t and c["program"] == p))
            for r in fuzzers[f][t][p]:
                fuzzer, cid = next((c["fuzzer"],c["cid"]) for c in campaigns
                                   if c["target"] == t and c["program"] == p and c["run"] == r)
                c_path = os.path.join(root, f"{fuzzer}_{t}_{p}_{r}_{cid}")
                fuzzers[f][t][p][r] = {
                    "path": c_path,
                    "fuzzer_cls": campaigns[0]["fuzzer"]
                }

afl = AFLFuzzer("/root/fuzzers/afl/")
aflfast = AFLFastFuzzer("/root/fuzzers/aflfast/")
moptafl = MOptAFLFuzzer("/root/fuzzers/moptafl/")
fairfuzz = FairFuzzFuzzer("/root/fuzzers/fairfuzz/")
angora = AngoraFuzzer("/root/fuzzers/angora/")
honggfuzz = honggfuzzFuzzer("/root/fuzzers/honggfuzz")

work_dir = "/root/postproc"

fuzzer_props = {
    "afl": {},
    "aflfast": {},
    "fairfuzz": {},
    "moptafl": {},
    "honggfuzz": {},
    "angora": {"ANGORA_TAINT_RULE_LIST": os.path.join(MAGMA_DIR, "rules/abi.txt")}
}

target_props = {
    "libpng16": {
        "bugs": [1,2,3,4,5,7,8],
        "programs": [("readpng", "@@")]
    },
    "libtiff4": {
        "bugs": [9,10,11,12,13,14,15,16,17,18,19,20,21,22],
        "programs": [("tiffcp", "-i @@ /dev/null")]
    },
    "libxml2": {
        "bugs": [23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41],
        "programs": [("xmllint", "--valid --oldxml10 --push --memory @@")]
    },
    "poppler": {
        "bugs": [42,43,45,46,47,48,49,50,51,52],
        "programs": [("pdftoppm", "-mono -cropbox @@"), ("pdfimages", "@@ /tmp/out")]
    }
}

def findings(campaign):
    def remove(l, s):
        x = l.copy()
        if s in x:
            x.remove(s)
        return x

    f = filter(lambda x: os.path.basename(x[0]).startswith(("crashes","hangs", "wd")), os.walk(campaign))
    inputs = []
    for root,_,files in f:
        files = remove(files, "README.txt") # TODO remove honggfuzz text files
        paths = list(map(lambda x: os.path.join(root, x), files))
        inputs.extend(paths)
    return inputs

timeout = 0.02
memlimit = 50 # TODO currently unused

tmpin = os.path.realpath("tmp.in")
if "shmem" in locals() or "shmem" in globals():
    del shmem
shmem = monitor.ShmemRawArray(2 * ctypes.c_int, 100, "MAGMAT", force=True, create=True)

fuzzer_detects = dict.fromkeys(fuzzers.keys())

for f in fuzzers:
    f_dir = os.path.join(work_dir, f)
    try:
        os.mkdir(f_dir)
        exists = False
    except:
        exists = True
    fuzzer_detects[f] = {
        "crash": dd(int),
        "hang": dd(int),
        "undetected": dd(int),
        "new_hang": 0,
        "new_crash": 0,
        "unknown": 0
    }
    for t in fuzzers[f]:
        fuzzer = locals()[f]
        if not exists:
            print(f"Compiling {t} for {f}")
            programs = fuzzer.compile(t, f_dir, config=False, MAGMA_STORAGE="MAGMAT", CFLAGS="-fsanitize=address", CXXFLAGS="-fsanitize=address", **fuzzer_props[f])
        else:
            programs = []
            for root, _, files in os.walk(f_dir, topdown=False):
                for file in files:
                    p_name = os.path.basename(file)
                    if p_name == "monitor":
                        continue
                    p_path = os.path.join(root, file)
                    program = {"program": p_name, "path": p_path}
                    programs += [program]
                break

        for p in fuzzers[f][t]:
            print(f"[{f}] Testing {p} crash reports")
            program = next(x for x in programs if x["program"] == p)
            p_path = program["path"]
            p_args = next(x[1] for x in target_props[t]["programs"] if x[0] == p)
            for r in fuzzers[f][t][p]:
                print(f"[{f}][{p}] Campaign {r}")
                c_path = fuzzers[f][t][p][r]["path"]
                inputs = findings(c_path)

                for i in inputs:
                    shmem.__init__(*([(ctypes.c_int * 2)(*[0,0])]*MAGMA_LENGTH)) # clears the counters
                    copyfile(i, tmpin)

                    proc_env = os.environ.copy()
                    proc_env.update({"ASAN_OPTIONS": "exitcode=128"})
                    proc = subprocess.Popen([p_path] + p_args.replace("@@", tmpin).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=proc_env)
                    hang = False
                    try:
                        sout, serr = proc.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired as e:
                        proc.kill()
                        sout, serr = proc.communicate()
                        hang = True

                    if shmem[0][0] == 0 and not hang:
                        print("Out of sync")

                    try:
                        bug = next(x[0] for x in enumerate(shmem) if x[1][1] != 0)
                    except StopIteration:
                        bug = 0

                    if not hang:
                        crash = proc.returncode > 127 and proc.returncode <= 128 + 64 # a signal was received

                    if hang or crash:
                        if bug > 0:
                            fuzzer_detects[f]['hang' if hang else 'crash'][bug] += 1
                        else:
                            fuzzer_detects[f][f"new_{'hang' if hang else 'crash'}"] += 1
                    elif bug > 0:
                        fuzzer_detects[f]['undetected'][bug] += 1
                    else:
                        fuzzer_detects[f]['unknown'] += 1

print(fuzzer_detects)
