import os
import argparse
import pandas as pd
from config import *
from formatters import format_latex_tabular

def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]

def parse_campaign_log(campaign):
    reached = dict.fromkeys(MAGMA_TARGETS[campaign["target"]]["bugs"])
    triggered = dict.fromkeys(MAGMA_TARGETS[campaign["target"]]["bugs"])

    df = pd.read_csv(campaign["m_path"], sep='\t', header=0, index_col="TIME")
    for bug in MAGMA_TARGETS[campaign["target"]]["bugs"]:
        bid = str(bug).zfill(3)
        R = df[df[f"{bid}_R"] > 0]
        if not R.empty:
            reached[bug] = R.index[0]
        T = df[df[f"{bid}_T"] > 0]
        if not T.empty:
            triggered[bug] = T.index[0]

    return reached, triggered

def parse_fuzzer_campaigns(fuzzer_dir, parse_logs=True):
    for root,campaign_dirs,_ in os.walk(fuzzer_dir):
        break
    campaigns = [(os.path.join(root, dirname),dirname.split('_')) for dirname in campaign_dirs]
    campaigns = [
        {
            "fuzzer": c_params[0],
            "target": c_params[1],
            "program": c_params[2],
            "run": c_params[3],
            "cid": c_params[4],
            "c_path": c_path,
            "m_path": os.path.join(c_path, "monitor.txt")
        } for c_path, c_params in campaigns
    ]

    targets = set(c["target"] for c in campaigns)
    fuzzer = dict.fromkeys(targets)
    for t in fuzzer:
        fuzzer[t] = dict.fromkeys(set(c["program"] for c in campaigns if c["target"] == t))
        for p in fuzzer[t]:
            fuzzer[t][p] = dict.fromkeys(set(c["run"] for c in campaigns if c["target"] == t and c["program"] == p))
            for r in fuzzer[t][p]:
                c = next(c for c in campaigns
                        if c["target"] == t and c["program"] == p and c["run"] == r)
                fuzzer[t][p][r] = c
                if parse_logs:
                    reached, triggered = parse_campaign_log(c)
                    fuzzer[t][p][r].update(
                        {
                            "reached": reached,
                            "triggered": triggered
                        }
                    )
    return fuzzer

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
    parser.add_argument("--out_format",
        choices=["latex"],
        default="latex",
        help="The format with which to print the parsed outputs.")
    args = parser.parse_args()

    fuzzers = parse_all_fuzzers(args.work_dir, parse_logs=True)
    if args.out_format == "latex":
        order = ["afl", "aflfast", "moptafl", "fairfuzz", "honggfuzz", "angora"]
        print(format_latex_tabular(fuzzers, order))
    pass

if __name__ == '__main__':
    main()
