import pandas as pd
from pandas import DataFrame
from math import sqrt
import numpy as np
from Metric import Metric
from BenchmarkData import BenchmarkData
from math import inf
from lifelines import KaplanMeierFitter
from lifelines.utils import restricted_mean_survival_time
import scipy.stats as ss

def average_time_to_metric_data(bd,metric) :
    """
    Reshapes the intial dataframe in a way to obtain the mean and
    variance of the number of bugs that have satisfied the metric

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }
    """

    #Select only bugs that satisfy the metric and then calculate the mean time by grouping
    df = bd.get_frame()
    average_time = df.iloc[df.index.get_level_values('Metric') == metric].mean(level=['Fuzzer','Target','Program'])
    return average_time

def expected_time_to_trigger_data(bd) :
    """
    Reshapes the data to compute the expected time-to-trigger for every
    triggered bug. It also computes the aggregate time for every bug, which
    can be used to sort the bugs

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }
    """

    def expected_time_to_bug(N,M,t):
        """
        Helper function to compute the expected time to trigger for every bug

        :param    N:    { Levels = ['Fuzzer', 'Target','Program','BugID'].
                          Contains the total number of campaigns in every
                          level. }
        :type     N:    { MultiIndex Dataframe }

        :param    M:    { Levels = ['Fuzzer', 'Target','Program','BugID'].
                          Contains the total number of campaigns where bug
                          with BugID was triggered. }
        :type     M:    { MultiIndex Dataframe }

        :param    t:    { Levels = ['Fuzzer', 'Target','Program','BugID'].
                          Contains the mean time to trigger for every bug
                          with BugID. }
        :type     t:    { MultiIndex Dataframe }
        """

        N_minus_M = N - M
        lambda_t = np.log(N / N_minus_M)
        ett = ((M * t) + N_minus_M * (bd.duration / lambda_t)) / N
        return ett


    df = bd.frame
    df_triggered = df[df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
    t = df_triggered.groupby(['Fuzzer','Target','Program','BugID'])['Time'].mean()
    M = df_triggered.groupby(['Fuzzer','Target','Program','BugID'])['Time'].count()
    N_raw = df.reset_index().groupby(['Fuzzer', 'Target', 'Program'])['Campaign'].nunique()
    N = N_raw.reindex_like(M)
    df_ett = expected_time_to_bug(N,M,t).groupby(['Fuzzer','Target','BugID']).min().droplevel(1).unstack().transpose()

    #Aggregate time computation
    #NOT COMPLETE
    #Extracting the program for which the bug did best
    prog_bug = expected_time_to_bug(N,M,t).reset_index(name='Time')
    prog_bug = prog_bug.loc[prog_bug.groupby(['Fuzzer','Target','BugID'])['Time'].idxmin()]
    prog_bug = prog_bug.set_index(['Fuzzer','Target','Program','BugID'])

    #Computing the average time to trigger bug over all fuzzers and libraries including all programs
    M_agg = df_triggered.groupby(['Fuzzer','Target','Program','BugID'])['Time'].count()
    t_agg = df_triggered.groupby(['Fuzzer','Target','Program','BugID'])['Time'].sum()

    #Only considering the program where the bug did best
    M_agg = M_agg[M_agg.index.isin(prog_bug.index)]
    t_agg = t_agg[t_agg.index.isin(prog_bug.index)]
    M_agg = M_agg.groupby('BugID').sum()
    t_agg = t_agg.groupby('BugID').sum() / M_agg

    #Counting the number of campaigns for each bug in every program,target and fuzzer
    def count_campaigns(group):
        target = next(iter(group.groupby(['Target', 'Program']).groups.keys()))
        sum = 0
        for fuzzer in N_raw.index.levels[0]:
            idx = (fuzzer, *target)
            if idx in N_raw:
                sum += N_raw.loc[idx]
        return sum
    N_agg = prog_bug.groupby('BugID').apply(count_campaigns)

    agg = expected_time_to_bug(N_agg,M_agg,t_agg)
    agg = agg.sort_values()
    return df_ett, agg

def unique_bugs_per_target_data(bd, metric):
    """
    Returns for each Campaign the number of unique bugs triggered

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }
    """

    def compute_p_values(series):
        """
        Computes the p_values used in the statistical significance plot
        for a specific target

        :param series: { Data of a target }
        :type  series: { Series }
        """

        #For every fuzzer we gather in a list the number of times a bug was found
        #Entry 0 in the list is for campaign 0
        fuzzer_data = series.groupby('Fuzzer').apply(list)
        fuzzer_label = fuzzer_data.index.tolist()
        #Constructing the index from the cross product of the fuzzer_label
        #The index has already the shape of the targeted p_value dataframe
        index = pd.MultiIndex.from_product([fuzzer_label,fuzzer_label],names=['Outer','Inner'])
        #Creation of the p_value Dataframe with the previously computed index.
        #Index has to been reset such that the multi index values can be passed as argument to the lambda function
        p_values = pd.DataFrame(index=index,columns=['p_value']).fillna(np.nan)
        p_values = p_values.apply(lambda f: two_sided_test(*f.name,fuzzer_data), axis=1)
        #Unstacking the Dataframe gives it the expected 2 dimensional shape for a p_value array
        return p_values.unstack()

    def two_sided_test(f1, f2, fuzzer_data):
        """
        Helper function to compute the p_value between two fuzzer_label
        """

        if f1 == f2 or set(fuzzer_data[f1]) == set(fuzzer_data[f2]):
            return np.nan
        else:
            return ss.mannwhitneyu(fuzzer_data[f1],fuzzer_data[f2], alternative='two-sided').pvalue

    df = bd.frame
    df = df.iloc[df.index.get_level_values('Metric') == metric]
    #Extract the number of unique bugs per campaign
    unique_bugs = df.reset_index().groupby(['Fuzzer','Target','Campaign'])['BugID'].nunique()
    #Unstack and stack back to fill the missing campaign values in case there is
    #not the same number of campaigns for every target/fuzzer.
    #This is needed because the Mann-Whitney U-test requires the same number of
    #samples for both sample sets.
    unique_bugs = unique_bugs.unstack('Campaign', fill_value=0) \
                             .stack(level=0)

    agg = unique_bugs.groupby(['Fuzzer', 'Target']) \
                     .apply(lambda d: pd.DataFrame([d.mean(), d.std()],
                                                   index=['Mean', 'Std']) \
                                        .unstack()
                      )

    p_values = unique_bugs.groupby('Target') \
                          .apply(lambda d: compute_p_values(
                                            d.reset_index('Target', drop=True)
                                           )
                           )

    return unique_bugs, agg, p_values

def number_of_unique_bugs_found_data(bd):
    """
    Computed the total number of found bugs by each fuzzer

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }
    """

    df = bd.frame
    #Extracting all found bugs
    df_triggered = df.iloc[df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
    #Reseting the index is necessary to get the number of unique bugs triggered by each fuzzer
    num_trigg = df_triggered.reset_index().groupby(['Fuzzer'])['BugID'].nunique().to_frame()
    num_trigg.columns = ['Bugs']
    return num_trigg


def bug_list(bd,fuzzer,target,metric):
    """
    Returns the list of bugs along side with the metric time
    A dataframe indexed by the different bugs with columns containing the time for one campaign
    A time can be Nan

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param fuzzer: { chosen fuzzer }
    :type  fuzzer: { string }

    :param target: { chosen target }
    :type  target: { string }

    :param metric: { chosen metric }
    :type  metric: { string }
    """

    df = bd.get_frame()
    #Extracting the bug fullfilling the metric by putting there metric times into a list
    df_bugs = df.iloc[df.index.get_level_values('Metric') == metric]
    df_bugs = df_bugs.loc[fuzzer,target].groupby('BugID')['Time'].apply(list)
    #Preparing the new index to be the bugs
    index = df_bugs.index.tolist()
    #Reseting the index and converting the data in the column Time into a new Dataframe
    d = pd.DataFrame(df_bugs.reset_index()['Time'].to_list(),index = index)
    return d

def line_plot_data(bd,target,metric) :
    """
    Returns a Dataframe that has a row for every fuzzer and 3 columns (x,y,ci) representing repectively
    the datapoints to place on x and y axis alongside with the error margin

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param target: { chosen target }
    :type  target: { string }

    :param metric: { chosen metric }
    :type  metric: { string }
    """

    def get_step_value(fuzzer,x_values, campaigns):
        """
        For every x_value we have to compute the step values
        """

        #Extracting data for the correct fuzzer
        df_fuzz = campaigns.iloc[campaigns.index.get_level_values('Fuzzer') == fuzzer]

        campaigns_data = df_fuzz.groupby(['Campaign'])['Time'].apply(lambda x : sorted(list(x)))
        num_campaigns = len(campaigns_data.index)

        #The series has the sorted time to metric for every bug as index and as value
        def step_val(series,x):
            serie = series[series.index <= x]
            if (serie.empty):
                return 0
            return serie.iloc[-1] + 1
        #The series has to been inverted, the index has to be the time values and the actual values have to be the index
        ##For each of the values in x we compute an array containing a step_value for each campaign
        y_values = [[step_val(pd.Series([i for i in range(0,len(campaigns_data.loc[str(campaign)]))],index=campaigns_data.loc[str(campaign)]), x)
                    for campaign in range(0,num_campaigns)] for x in x_values]
        return y_values


    df = bd.get_frame()
    df_metric = df.iloc[df.index.get_level_values('Metric') == metric]
    df_lib = df_metric.iloc[df_metric.index.get_level_values('Target') == target]

    #For each unique BugID in each campaign in multiple Programs, only retain the smallest time to metric
    df_lib = df_lib.groupby(['Fuzzer','Target','Campaign','BugID']).min()

    x_plot = df_lib.groupby(['Fuzzer'])['Time'].apply(lambda x : sorted(set(x))).to_frame()
    x_plot.columns = ['x']
    y_plot = x_plot
    index = x_plot.index
    #Reseting index to be able to pass index values as argument
    y_plot = y_plot.reset_index()
    y_plot = y_plot.apply(lambda f : get_step_value(f['Fuzzer'],f['x'],df_lib),axis=1).to_frame()
    y_plot.index = index
    y_plot.columns = ['y']
    df_aggplot = x_plot
    df_aggplot['y'] = y_plot
    #Error margin computation
    df_aggplot['ci'] = df_aggplot['y'].apply(lambda x : [1.96 * np.nanstd(i) / np.nanmean(i) for i in x])
    df_aggplot['y'] = df_aggplot['y'].apply(lambda x : [np.nanmean(i) for i in x])

    #For every fuzzer we get the max value and the min value for x and y
    #Then we have to recompute the max between them
    x_max = max([max(x) for x in df_aggplot['x']])
    x_min = min([min(x) for x in df_aggplot['x']])
    y_max = max([max(y) for y in df_aggplot['y']])

    return df_aggplot, x_max, y_max, x_min

def bug_survival_data(bd):
    def fit_kmf_one(group, supergroup_name, N):
        fuzzer = group.name[0]
        target, program = supergroup_name[:2]
        if (fuzzer, target, program) in N:
            N = N.loc[(fuzzer, target, program)]
        else:
            N = 1
        records = group.reset_index(drop=True)['Time'].reindex(np.arange(N))
        T = records.fillna(bd.duration)
        E = records.notnull()
        kmf = KaplanMeierFitter()
        kmf.fit(T, E, label='%s' % (fuzzer))
        return kmf

    def fit_kmf_all(group, N):
        def fillmissing(group, supergroup_name):
            target, program, bug = supergroup_name
            fuzzer = group.name
            metrics = set(['reached', 'triggered'])
            group_metrics = set(group['Metric'].unique())
            for metric in metrics.difference(group_metrics):
                new_row = pd.Series({
                    'Fuzzer': fuzzer,
                    'Target': target,
                    'Program': program,
                    'Campaign': 0,
                    'Metric': metric,
                    'BugID': bug
                })
                group = group.append(new_row, ignore_index=True)
            return group

        name = group.name
        fuzzers = N.index.get_level_values('Fuzzer').unique()
        fuzzers_in_group = group['Fuzzer'].unique()
        for fuzzer in fuzzers:
            if fuzzer in fuzzers_in_group:
                continue
            new_rows = [
                pd.Series({
                    'Fuzzer': fuzzer,
                    'Metric': 'reached'
                }),
                pd.Series({
                    'Fuzzer': fuzzer,
                    'Metric': 'triggered'
                }),
            ]
            group = group.append(new_rows, ignore_index=True)

        group = group.groupby('Fuzzer').apply(fillmissing, name).reset_index(drop=True)

        subgroups = group.groupby(['Fuzzer','Metric']).apply(fit_kmf_one, name, N)
        return subgroups

    df = bd.frame
    N = df.reset_index().groupby(['Fuzzer', 'Target', 'Program'])['Campaign'].nunique()
    kmf = df.reset_index() \
            .groupby(['Target', 'Program', 'BugID']) \
            .apply(fit_kmf_all, N)

    # get the mean survival time for every (target, program, bug, fuzzer, metric) tuple
    means = kmf.applymap(lambda k: restricted_mean_survival_time(k, bd.duration))
    # re-arrange the dataframe such that the columns are the metrics
    means = means.stack(level=0)
    # for every (target, bug, fuzzer) tuple, select the row corresponding to the program where the bug was triggered earliest
    means = means.loc[means.groupby(['Target', 'BugID', 'Fuzzer'])[Metric.TRIGGERED.value].idxmin()]
    # re-arrange dataframe so that index is (target, bug) and columns are (fuzzer, metric)
    means = means.droplevel('Program').stack().unstack(-2).unstack()

    return kmf, means
