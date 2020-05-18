#!/usr/bin/env python3

import os
import argparse
import pandas as pd
from config import *
from formatters import format_latex_tabular
from collections import defaultdict
import json

def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]

def parse_campaign_log(log_path):
    reached = {}
    triggered = {}

    df = pd.read_csv(log_path, sep=',', header=0, index_col="TIME")
    bugs = set(x[:-2] for x in df.columns)
    for bug in bugs:
        R = df[df[f"{bug}_R"] > 0]
        if not R.empty:
            reached[bug] = int(R.index[0])
        T = df[df[f"{bug}_T"] > 0]
        if not T.empty:
            triggered[bug] = int(T.index[0])

    return reached, triggered

def parse_fuzzer_campaigns(fuzzer_dir, parse_logs=True):
    def path_split_last(path, n):
        sp = []
        for i in range(n):
            path, tmp = os.path.split(path)
            sp = [tmp] + sp
        return sp
    def default_to_regular(d):
        if isinstance(d, defaultdict):
            d = {k: default_to_regular(v) for k, v in d.items()}
        return d

    ddr = lambda: defaultdict(ddr)
    logs = []
    for root,dirs,files in os.walk(fuzzer_dir):
        if not dirs:
            logs.extend(os.path.join(root, file) for file in files)
    fuzzerdict = ddr()
    for log in logs:
        fuzzer, target, program, run, _ = path_split_last(log, 5)
        if parse_logs:
            reached, triggered = parse_campaign_log(log)
            fuzzerdict[target][program][run] = {
                "fuzzer": fuzzer,
                "reached": reached,
                "triggered": triggered
            }
        else:
            fuzzerdict[target][program][run] = {
                "fuzzer": fuzzer,
                "m_path": log
            }
    return default_to_regular(fuzzerdict)

def parse_all_fuzzers(work_dir, parse_logs=True):
    fuzzers = {}
    for root, dirs, files in walklevel(work_dir, level=1):
        if not bool(fuzzers):
            fuzzers = fuzzers.fromkeys(dirs)
            continue
        f = os.path.basename(root)
        fuzzers[f] = parse_fuzzer_campaigns(root, parse_logs)
    return fuzzers

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("work_dir",
        help="The path to the directory where all fuzzers' campaigns are stored.")
    parser.add_argument("--out-format",
        choices=["latex", "json"],
        default="latex",
        help="The format with which to print the parsed outputs.")
    parser.add_argument("--out-file",
        default="-",
        help="The file to which the output will be written, or - for stdout.")
    args = parser.parse_args()

    fuzzers = parse_all_fuzzers(args.work_dir, parse_logs=True)
    if args.out_format == "latex":
        order = ["afl", "aflfast", "moptafl", "fairfuzz", "honggfuzz", "angora"]
        data = format_latex_tabular(fuzzers, order).encode()
    elif args.out_format == "json":
        data = json.dumps(fuzzers).encode()

    if args.out_file == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.out_file, "wb") as f:
            f.write(data)

if __name__ == '__main__':
    main()
