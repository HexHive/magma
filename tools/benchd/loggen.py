#!/usr/bin/env python3
import os
import subprocess
import shutil
from collections import defaultdict as dd
import errno
from multiprocessing import Value, Lock, Pool, Manager
from tempfile import mkdtemp
import argparse
import pandas as pd

def find_all_tarballs(workdir):
    for root, dirs, files in os.walk(workdir):
        for file in files:
            if file.endswith(".tar"):
                yield os.path.join(root, file)

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
    monitor = subprocess.check_output(f'tar -tf "{tarball}" | grep -Po ".*monitor" | uniq', shell=True)
    monitor = monitor.decode().rstrip()
    ccount = len(monitor.split("/"))
    os.system(f'tar -xf "{tarball}" --strip-components={ccount} -C "{dest}" {monitor}')

def generate_monitor_log(dump_dir, out):
    def row_generator():
        for _, _, files in os.walk(dump_dir):
            break

        if 'tmp' in files:
            files.remove('tmp')
        files.sort(key=int)
        for timestamp in files:
            fname = os.path.join(dump_dir, timestamp)
            try:
                df = pd.read_csv(fname, sep=',', header=0)
                df['TIME'] = timestamp
                df = df.set_index('TIME')
                yield df
            except pd.errors.EmptyDataError:
                continue
    try:
        log = pd.concat(row_generator())
        log.to_csv(out, sep=',', header=True)
    except:
        pass

def ddr():
    return dd(ddr)

def path_split_last(path, n):
    sp = []
    for i in range(n):
        path, tmp = os.path.split(path)
        sp = [tmp] + sp
    return sp

def ensure_dir(dirname):
    """
    Ensure that a named directory exists; if it does not, attempt to create it.
    """
    try:
        os.makedirs(dirname)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def process_one_campaign(bol, log_dir, tmp_dir):
    fuzzer, target, program, _, _ = path_split_last(bol, 5)

    lock.acquire()
    try:
        run = fuzzers[fuzzer][target][program].value
        fuzzers[fuzzer][target][program].value += 1
    finally:
        lock.release()

    run_dir = os.path.join(log_dir, fuzzer, target, program, str(run))
    ensure_dir(run_dir)

    print("Processing", run_dir)

    if not os.path.isfile(os.path.join(run_dir, "monitor.txt")):
        tmp_dir = mkdtemp(dir=tmp_dir)
        extract_monitor_dumps(bol, tmp_dir)
        try:
            generate_monitor_log(tmp_dir, os.path.join(run_dir, "monitor.txt"))
        finally:
            clear_dir(tmp_dir)
            os.rmdir(tmp_dir)

    print("Processed", run_dir)


def generate_all_monitor_logs(workdir, outdir, workers):
    def init(l, f):
        global lock
        global fuzzers
        lock = l
        fuzzers = f

    fuzzers = ddr()
    log_dir = os.path.join(outdir, "logs")
    tmp_dir = os.path.join(outdir, "tmp")
    ensure_dir(log_dir)
    ensure_dir(tmp_dir)

    for bol in find_all_tarballs(workdir):
        fuzzer, target, program, _, _ = path_split_last(bol, 5)
        fuzzers[fuzzer][target][program] = Value('i', 0)

    lock = Lock()

    with Pool(processes=workers, initializer=init, initargs=(lock,fuzzers)) as pool:
        pool.starmap(process_one_campaign,
            ((bol, log_dir, tmp_dir) for bol in find_all_tarballs(workdir))
        )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers",
        default=4,
        help="The number of concurrent processes to launch.")
    parser.add_argument("work_dir",
        help="The path to the directory where all fuzzers' campaigns are stored.")
    parser.add_argument("out_dir",
        help="The path to the directory where logs and temp files will be stored.")

    args = parser.parse_args()
    generate_all_monitor_logs(args.work_dir, args.out_dir, int(args.workers))

if __name__ == '__main__':
    main()
