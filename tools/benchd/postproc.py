from config import *
from benchd import BENCHD_FUZZERS
from monitor import ShmemRawArray
from logparse import parse_all_fuzzers

import argparse
import ctypes
from collections import defaultdict as dd
import os
import pprint
import shlex
from shutil import copyfile
import subprocess

def list_findings(campaign):
    def remove(l, s):
        x = l.copy()
        if s in x:
            x.remove(s)
        return x

    f = filter(lambda x: os.path.basename(x[0]).startswith(("crashes","hangs")), os.walk(campaign))
    inputs = []
    for root,_,files in f:
        files = remove(files, "README.txt") # TODO remove honggfuzz text files
        paths = list(map(lambda x: os.path.join(root, x), files))
        inputs.extend(paths)
    return inputs

def process_campaign_findings(campaign, bin_path, bin_args, timeout=0.02, memlimit=50, povs=False):
    shmem = ShmemRawArray(MAGMA_TYPE, MAGMA_LENGTH, "MAGMAT", force=True, create=True)
    tmpin = os.path.realpath("tmp.in")
    store_type = list if povs else int
    detections = {
        "crash": dd(store_type),
        "hang": dd(store_type),
        "undetected": dd(store_type),
        "new_hang": store_type(),
        "new_crash": store_type(),
        "unknown": store_type()
    }

    c_path = campaign["c_path"]
    inputs = list_findings(c_path)
    for i in inputs:
        shmem.__init__(*([MAGMA_TYPE_INIT]*MAGMA_LENGTH)) # clears the counters
        copyfile(i, tmpin)
        proc_env = os.environ.copy()
        proc_env.update({"ASAN_OPTIONS": "exitcode=128"})
        proc = subprocess.Popen([bin_path] + shlex.split(bin_args.replace("@@", tmpin)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=proc_env)
        hang = False
        try:
            sout, serr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            proc.kill()
            sout, serr = proc.communicate()
            hang = True

        # Check if the MAGMA exec counter had been incremented (bug "0" reached)
        if shmem[0][0] == 0:
            if not hang:
                print("Out of sync")
            else:
                print(f"Program timed out before magma_init()! ({i})")

        # Get the bug number (index) whose trigger counter is non-zero
        bug = next((x[0] for x in enumerate(shmem) if x[1][1] != 0), 0)

        if not hang:
            # A signal received (e.g. SEGFAULT) results in a special exit code
            crash = proc.returncode > 127 and proc.returncode <= 128 + 64

        store = [i] if povs else 1
        if hang or crash:
            if bug > 0:
                detections['hang' if hang else 'crash'][bug] += store
            else:
                detections[f"new_{'hang' if hang else 'crash'}"] += store
        elif bug > 0:
            detections['undetected'][bug] += store
        else:
            detections['unknown'] += store

    try:
        os.unlink(tmpin)
    except FileNotFoundError:
        pass

    # convert defaultdict to dict for pretty printing
    detections["crash"] = dict(detections["crash"])
    detections["hang"] = dict(detections["hang"])
    detections["undetected"] = dict(detections["undetected"])
    return detections

def process_fuzzer_campaigns(fuzzer, targets, bin_dir, povs=False):
    fuzzer_detects = dict.fromkeys(targets.keys())
    programs = []

    try:
        os.mkdir(bin_dir)
        exists = False
    except:
        exists = True
        for root, _, files in os.walk(bin_dir, topdown=False):
            for file in files:
                p_name = os.path.basename(file)
                if p_name == "monitor":
                    continue
                p_path = os.path.join(root, file)
                program = {"program": p_name, "path": p_path}
                programs += [program]
            break

    for t in targets:
        fuzzer_detects[t] = dict.fromkeys(targets[t].keys())
        if not exists:
            print(f"Compiling {t} for {fuzzer}")
            programs += BENCHD_FUZZERS[fuzzer]["instance"].compile(t, bin_dir, config=False, MAGMA_STORAGE="MAGMAT", CFLAGS="-fsanitize=address", CXXFLAGS="-fsanitize=address", **BENCHD_FUZZERS[fuzzer]["env"])

        for p in targets[t]:
            fuzzer_detects[t][p] = dict.fromkeys(targets[t][p].keys())
            print(f"[{fuzzer}] Testing {p} crash reports")
            program = next(x for x in programs if x["program"] == p)
            p_path = program["path"]
            p_args = next(x[1] for x in MAGMA_TARGETS[t]["programs"] if x[0] == p)
            for r in targets[t][p]:
                print(f"[{fuzzer}][{p}] Campaign {r}")
                fuzzer_detects[t][p][r] = process_campaign_findings(targets[t][p][r], p_path, p_args, povs=povs)

    return fuzzer_detects

def process_all_fuzzers(work_dir, build_dir, povs=False):
    fuzzers = parse_all_fuzzers(work_dir, parse_logs=False)
    detections = dict.fromkeys(fuzzers.keys())

    for f in fuzzers:
        bin_dir = os.path.join(build_dir, f)
        detections[f] = process_fuzzer_campaigns(f, fuzzers[f], bin_dir, povs=povs)

    return detections

def save_povs(detections, pov_dir):
    campaigns = [(f,t,p,r,c)
        for f, targets in detections.items()
        for t, programs in targets.items()
        for p, campaigns in programs.items()
        for r, c in campaigns.items()]

    # First get PoVs that map to known bugs
    bugs = (b
        for t, props in MAGMA_TARGETS.items()
        for b in props["bugs"])
    bug_povs = {bug: {
            typ: [
                (f, t, p, r, pov) for f,t,p,r,c in campaigns
                for b, povs in c[typ].items() if b == bug
                for pov in povs
            ] for typ in ("crash", "hang", "undetected")
        } for bug in bugs
    }

    # Then get PoVs that map to new or unknown faults
    new_povs = {typ: [
            (f, t, p, r, pov) for f,t,p,r,c in campaigns
            for pov in c[typ]
        ] for typ in ("new_crash", "new_hang", "unknown")
    }

    # Now, save all PoVs, aptly named
    i = 0
    for bug, typs in bug_povs.items():
        for typ, povs in typs.items():
            for f, t, p, r, pov in povs:
                pov_name = f"{str(bug).zfill(3)}_{typ}_{f}_{t}_{p}_{r}_{i}"
                copyfile(pov, os.path.join(pov_dir, pov_name))
                print(f"Saved bug PoV: {pov_name}")
                i += 1
    for typ, povs in new_povs.items():
        for f, t, p, r, pov in povs:
            pov_name = f"{typ}_{f}_{t}_{p}_{r}_{i}"
            copyfile(pov, os.path.join(pov_dir, pov_name))
            print(f"Saved new PoV: {pov_name}")
            i += 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("work_dir",
        help="The path to the directory where all fuzzers' campaigns are stored.")
    parser.add_argument("build_dir",
        help="The path to the directory where compiled binaries are/will be stored.")
    parser.add_argument("--save-povs",
        help="The path to the directory where PoVs will be saved.")
    args = parser.parse_args()

    povs = "save_povs" in args
    detections = process_all_fuzzers(args.work_dir, args.build_dir, povs=povs)

    if not povs:
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(detections)
    else:
        save_povs(detections, args.save_povs)

if __name__ == '__main__':
    main()
