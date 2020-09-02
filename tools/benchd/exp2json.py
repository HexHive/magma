#!/usr/bin/env python3

from collections import defaultdict
from multiprocessing import Pool
from tempfile import mkdtemp
import os
import pandas as pd
import shutil
import subprocess
import json
import argparse
import errno
import csv

ddr = lambda: defaultdict(ddr)

def parse_args():
    parser = argparse.ArgumentParser(description=(
        "Collects data from the experiment workdir and outputs a summary as "
        "a JSON file."
    ))
    parser.add_argument("--workers",
        default=4,
        help="The number of concurrent processes to launch.")
    parser.add_argument("workdir",
        help="The path to the Captain tool output workdir.")
    parser.add_argument("outfile",
        default="-",
        help="The file to which the output will be written, or - for stdout.")

    return parser.parse_args()

def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        num_sep_this = root.count(os.path.sep)
        yield root, dirs, files, (num_sep_this - num_sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]

def path_split_last(path, n):
    sp = []
    for i in range(n):
        path, tmp = os.path.split(path)
        sp = [tmp] + sp
    return sp

def find_campaigns(workdir):
    ar_dir = os.path.join(workdir, "ar")
    for root, dirs, files, level in walklevel(ar_dir, 3):
        if level == 3:
            for run in dirs:
                path = os.path.join(root, run)
                yield path

def ensure_dir(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def clear_dir(path):
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def extract_monitor_dumps(tarball, dest):
    clear_dir(dest)
    # get the path to the monitor dir inside the tarball
    monitor = subprocess.check_output(f'tar -tf "{tarball}" | grep -Po ".*monitor" | uniq', shell=True)
    monitor = monitor.decode().rstrip()
    # strip all path components until and excluding the monitor dir
    ccount = len(monitor.split("/")) - 1
    os.system(f'tar -xf "{tarball}" --strip-components={ccount} -C "{dest}" {monitor}')

def generate_monitor_df(dumpdir):
    def row_generator():
        files = os.listdir(dumpdir)

        if 'tmp' in files:
            files.remove('tmp')
        files.sort(key=int)
        for timestamp in files:
            fname = os.path.join(dumpdir, timestamp)
            try:
                with open(fname, newline='') as csvfile:
                    reader = csv.DictReader(csvfile)
                    row = next(reader)
                    row['TIME'] = timestamp
                    yield row
            except StopIteration:
                continue
    try:
        rows = list(row_generator())
        df = pd.DataFrame(rows)
        df.set_index('TIME', inplace=True)
        df.fillna(0, inplace=True)
        df = df.astype(int)
        del rows
        return df
    except:
        pass

def process_one_campaign(path):
    print("Processing", path)
    fuzzer, target, program, run = path_split_last(path, 4)

    tarball = os.path.join(path, "ball.tar")
    istarball = False
    if os.path.isfile(tarball):
        istarball = True
        path = mkdtemp(dir=tmpdir)
        extract_monitor_dumps(tarball, path)
    try:
        df = generate_monitor_df(os.path.join(path, "monitor"))
    finally:
        if istarball:
            clear_dir(path)
            os.rmdir(path)
    return fuzzer, target, program, run, df

def collect_experiment_data(workdir, workers):
    def init(*args):
        global tmpdir
        tmpdir, = tuple(args)

    experiment = ddr()
    tmpdir = os.path.join(workdir, "tmp")
    ensure_dir(tmpdir)

    with Pool(processes=workers, initializer=init, initargs=(tmpdir,)) as pool:
        results = pool.starmap(process_one_campaign,
            ((path,) for path in find_campaigns(workdir))
        )
        for fuzzer, target, program, run, df in results:
            experiment[fuzzer][target][program][run] = df
    return experiment

def get_ttb_from_df(df):
    reached = {}
    triggered = {}

    bugs = set(x[:-2] for x in df.columns)
    for bug in bugs:
        R = df[df[f"{bug}_R"] > 0]
        if not R.empty:
            reached[bug] = int(R.index[0])
        T = df[df[f"{bug}_T"] > 0]
        if not T.empty:
            triggered[bug] = int(T.index[0])
    return reached, triggered

def default_to_regular(d):
    if isinstance(d, defaultdict):
        d = {k: default_to_regular(v) for k, v in d.items()}
    return d

def get_experiment_summary(experiment):
    summary = ddr()
    for fuzzer, f_data in experiment.items():
        for target, t_data in f_data.items():
            for program, p_data in t_data.items():
                for run, df in p_data.items():
                    reached, triggered = get_ttb_from_df(df)
                    summary[fuzzer][target][program][run] = {
                        "reached": reached,
                        "triggered": triggered
                    }
    return default_to_regular(summary)

def main():
    args = parse_args()
    experiment = collect_experiment_data(args.workdir, int(args.workers))
    summary = get_experiment_summary(experiment)

    data = json.dumps(summary).encode()
    if args.outfile == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.outfile, "wb") as f:
            f.write(data)

if __name__ == '__main__':
    main()
