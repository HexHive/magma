#!/usr/bin/env python3

"""
Perform a survival analysis on the Magma time-to-bug results produced by the
exp2json.py script.

Results are output to CSV.

Author: Adrian Herrera
"""

from argparse import ArgumentParser, Namespace
from collections import defaultdict
from math import sqrt
from pathlib import Path
from typing import Tuple
import json
import warnings

from lifelines import KaplanMeierFitter
from lifelines.utils import restricted_mean_survival_time as rmst
import pandas as pd


ddr = lambda: defaultdict(ddr)


def parse_args() -> Namespace:
    """Parse command-line arguments."""
    parser = ArgumentParser(description='Magma survival analysis')
    parser.add_argument('-n', '--num-trials', type=int, required=True,
                        help='Number of trials')
    parser.add_argument('-t', '--trial-length', type=int, required=True,
                        help='Length of an individual trial (in seconds)')
    parser.add_argument('json', type=Path,
                        help='Magma-generated JSON file (containing bug data)')
    return parser.parse_args()


def get_time_to_bug(data: dict, num_trials: int) -> dict:
    """Get time-to-bug data from Magma JSON dictionary."""
    for fuzzer, f_data in data.items():
        for target, t_data in f_data.items():
            for program, p_data in t_data.items():
                bugs = ddr()
                for run, r_data in p_data.items():
                    for metric, m_data in r_data.items():
                        for bug, time in m_data.items():
                            if metric not in bugs[bug]:
                                bugs[bug][metric] = [None] * num_trials
                            bugs[bug][metric][int(run)] = time
                for bug, b_data in bugs.items():
                    yield dict(
                        target=target,
                        program=program,
                        fuzzer=fuzzer,
                        bug=bug,
                        **b_data,
                    )


def calc_survival(data: dict, trial_len: int) -> Tuple[float, float]:
    """Do the survival analysis."""
    df = pd.DataFrame(data)
    T = df.fillna(trial_len) / 60 / 60
    E = df.notnull()

    kmf = KaplanMeierFitter()
    kmf.fit(T, E)

    # Compute the restricted mean survival time and 95% confidence interval
    surv_time_mean, surv_time_var = rmst(kmf, t=trial_len / 60 / 60,
                                         return_variance=True)
    surv_time_var = abs(surv_time_var)
    surv_time_ci = 1.96 * (sqrt(surv_time_var) /
                           sqrt(len(kmf.survival_function_)))

    return surv_time_mean, surv_time_ci


def main():
    """The main function."""
    args = parse_args()

    # Ignore warnings
    warnings.simplefilter('ignore')

    survival_times = dict(target=[],
                          program=[],
                          bug=[],
                          fuzzer=[],
                          survival_time_reached=[],
                          survival_ci_reached=[],
                          survival_time_triggered=[],
                          survival_ci_triggered=[])

    # Read Magma JSON data
    with args.json.open() as inf:
        json_data = json.load(inf).get('results', {})

    # Do survival analysis on 'triggered' results
    for ttb in get_time_to_bug(json_data, args.num_trials):
        # Save table data
        survival_times['target'].append(ttb['target'])
        survival_times['program'].append(ttb['program'])
        survival_times['bug'].append(ttb['bug'])
        survival_times['fuzzer'].append(ttb['fuzzer'])

        for metric in ('reached', 'triggered'):
            if metric not in ttb:
                surv_time_mean = None
                surv_time_ci = None
            else:
                surv_time_mean, surv_time_ci = calc_survival(ttb[metric],
                                                             args.trial_length)

            survival_times[f'survival_time_{metric}'].append(surv_time_mean)
            survival_times[f'survival_ci_{metric}'].append(surv_time_ci)

    # Write to CSV
    order = ['bug', 'program', 'target', 'fuzzer']
    print(pd.DataFrame.from_dict(survival_times).sort_values(by=order).to_csv(index=False))


if __name__ == '__main__':
    main()
