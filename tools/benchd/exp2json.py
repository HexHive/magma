#!/usr/bin/env python3

import argparse
from collections import defaultdict
import csv
import errno
import json
import logging
from multiprocessing import Pool
import os
import shutil
import subprocess
import sys
from tempfile import mkdtemp

import pandas as pd

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
    parser.add_argument('-v', '--verbose', action='count', default=0,
        help=("Controls the verbosity of messages. "
            "-v prints info. -vv prints debug. Default: warnings and higher.")
        )
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
    for _ in range(n):
        path, tmp = os.path.split(path)
        sp = [tmp] + sp
    return (path, *sp)

def find_campaigns(workdir):
    ar_dir = os.path.join(workdir, "ar")
    for root, dirs, _, level in walklevel(ar_dir, 3):
        if level == 3:
            for run in dirs:
                # `run` directories always have integer-only names
                if not run.isdigit():
                    logging.warning((
                        "Detected invalid workdir hierarchy! Make sure to point "
                        "the script to the root of the original workdir."
                    ))
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
            logging.exception('Failed to delete %s. Reason: %s', file_path, e)

def extract_monitor_dumps(tarball, dest):
    clear_dir(dest)
    # get the path to the monitor dir inside the tarball
    monitor = subprocess.check_output(f'tar -tf "{tarball}" | grep -Po ".*monitor" | uniq', shell=True)
    monitor = monitor.decode().rstrip()
    # strip all path components until and excluding the monitor dir
    ccount = len(monitor.split("/")) - 1
    os.system(f'tar -xf "{tarball}" --strip-components={ccount} -C "{dest}" {monitor}')

def generate_monitor_df(dumpdir, campaign):
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
                logging.debug((
                    "Truncated monitor file contains no rows!"
                ))
                continue

    # use a list in case pd.DataFrame() can pre-allocate ahead of time
    rows = list(row_generator())
    if len(rows) == 0:
        workdir, _, fuzzer, target, program, run = path_split_last(campaign, 5)
        name = f"{fuzzer}/{target}/{program}/{run}"
        logfile = os.path.join(workdir, "log",
            f"{name.replace('/', '_')}_container.log")
        logging.warning(
            "%s contains no monitor logs. Check the corresponding campaign "
            "log file for more information: %s", name, logfile
        )

    df = pd.DataFrame(rows)
    df.set_index('TIME', inplace=True)
    df.fillna(0, inplace=True)
    df = df.astype(int)
    del rows
    return df

def process_one_campaign(path):
    logging.info("Processing %s", path)
    _, fuzzer, target, program, run = path_split_last(path, 4)

    tarball = os.path.join(path, "ball.tar")
    istarball = False
    if os.path.isfile(tarball):
        istarball = True
        dumpdir = mkdtemp(dir=tmpdir)
        logging.debug("Campaign is tarballed. Extracting to %s", dumpdir)
        extract_monitor_dumps(tarball, dumpdir)
    else:
        dumpdir = path

    df = None
    try:
        df = generate_monitor_df(os.path.join(dumpdir, "monitor"), path)
    except Exception as ex:
        name = f"{fuzzer}/{target}/{program}/{run}"
        logging.exception("Encountered exception when processing %s. Details: "
            "%s", name, ex)
    finally:
        if istarball:
            clear_dir(dumpdir)
            os.rmdir(dumpdir)
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
            if df is not None:
                experiment[fuzzer][target][program][run] = df
            else:
                # TODO add an empty df so that the run is accounted for
                name = f"{fuzzer}/{target}/{program}/{run}"
                logging.warning("%s has been omitted!", name)
    return experiment

def get_ttb_from_df(df):
    reached = {}
    triggered = {}

    bugs = set(x[:-2] for x in df.columns)
    logging.debug("Bugs found: %s", bugs)
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

def configure_verbosity(level):
    mapping = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG
    }
    # will raise exception when level is invalid
    numeric_level = mapping[level]
    logging.basicConfig(level=numeric_level)

def main():
    args = parse_args()
    configure_verbosity(args.verbose)
    experiment = collect_experiment_data(args.workdir, int(args.workers))
    summary = get_experiment_summary(experiment)

    output = {
        'results': summary,
        # TODO add configuration options and other experiment parameters
    }

    data = json.dumps(output).encode()
    if args.outfile == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.outfile, "wb") as f:
            f.write(data)

if __name__ == '__main__':
    main()
