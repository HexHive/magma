import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib import colors
from pandas import DataFrame
from math import sqrt
import seaborn as sns
import statistics
import math
from math import inf
import numpy as np
import os
import scikit_posthocs as sp
import scipy.stats as ss
from collections import defaultdict as dd


class Plots:
    # We initialize a few constants for the generator
    REACHED = "reached"
    TRIGGERED = "triggered"
    CAMPAIGN_DURATION = 83400
    NUMBER_OF_CAMPAIGNS_PER_LIBRARY = 10

    def __init__(self, data, path):
        self.data = data
        self.path = path
        self.ddr = lambda: dd(self.ddr)
        self.campaigns = list(str(x) for x in range(self.NUMBER_OF_CAMPAIGNS_PER_LIBRARY))

    def generate(self):
        """
        Generates all the avaalble graphs. Each method saves
        its own graph in the plots folder
        """
        self.line_plot_unique_bugs(self.REACHED)
        plt.clf()
        self.line_plot_unique_bugs(self.TRIGGERED)
        plt.clf()
        self.generate_plots_for_fuzzer()
        plt.clf()
        self.barplot_reached_vs_triggered_bugs_by_each_fuzzer_in_a_library()
        plt.clf()
        self.heat_map_expected_time_to_bug()
        plt.clf()
        self.heatmap_pvalue()
        plt.clf()
        self.barplot_mean_and_variance_of_bugs_found_by_each_fuzzer()
        plt.clf()
        self.boxplot_unique_bugs_reached_in_all_libraries()
        plt.clf()

    def get_all_targets_and_fuzzers(self):
        """
        Returns a pair of lists containing all
        targets for one and all fuzzers for the other
        """
        df = DataFrame(self.data)
        return list(df.index), list(df.columns)

    def combine_sublibrary_fuzz_results(self):
        """
        Sometimes a target has to be fuzzed multiple times over different parts of it
        This functions combines all the sublibrary fuzzing result
        """
        simplified_data = {}
        for fuzzer in self.data:
            simplified_data[fuzzer] = {}
            for library in self.data[fuzzer]:
                simplified_data[fuzzer][library] = {}
                for sublibraries in self.data[fuzzer][library]:
                    for campaign in self.data[fuzzer][library][sublibraries]:
                        if campaign not in simplified_data[fuzzer][library]:
                            simplified_data[fuzzer][library][campaign] = ([], [])
                        for conditions in self.data[fuzzer][library][sublibraries][campaign]:
                            if conditions == self.REACHED:
                                for reached_bugs, times in self.data[fuzzer][library][sublibraries][campaign][
                                    conditions].items():
                                    if reached_bugs not in [i[0] for i in
                                                            simplified_data[fuzzer][library][campaign][0]]:
                                        simplified_data[fuzzer][library][campaign][0].append((reached_bugs, times))

                            elif conditions == self.TRIGGERED:
                                for triggered_bugs, times in self.data[fuzzer][library][sublibraries][campaign][
                                    conditions].items():
                                    if triggered_bugs not in [i[0] for i in
                                                              simplified_data[fuzzer][library][campaign][1]]:
                                        simplified_data[fuzzer][library][campaign][1].append((triggered_bugs, times))

        return simplified_data

    def get_total_number_of_unique_bugs(self):
        """
        Returns a pair which of the first element contains ,for each fuzzer,library possibility
        ,the number of reached bugs. The second element of the pair contains the number of triggered
        bugs
        """
        d = self.combine_sublibrary_fuzz_results()

        totalBugsReached = {}
        totalBugsTriggered = {}
        for fuzzer, libraries in d.items():
            totalBugsReached[fuzzer] = {}
            totalBugsTriggered[fuzzer] = {}
            for library, campaigns in libraries.items():
                unique_reached = []
                unique_triggered = []
                for campaignNum, result in campaigns.items():
                    unique_triggered += [i[0] for i in result[1]]
                    unique_reached += [i[0] for i in result[0]]

                totalBugsReached[fuzzer][library] = len(set(unique_reached))
                totalBugsTriggered[fuzzer][library] = len(set(unique_triggered))

        return totalBugsReached, totalBugsTriggered

    def get_mean_and_deviation_of_number_of_triggered_bugs(self):
        """
        Computes the mean and the standard deviation of the number of reached and triggered
        campaigns over all campaigns ran over a target with a fuzzer

        """
        number_of_campaigns = self.get_number_of_campaigns_per_fuzzer_library()
        d = self.combine_sublibrary_fuzz_results()
        mean_deviation_reached = self.ddr()
        mean_deviation_triggered = self.ddr()
        for fuzzer, libraries in d.items():
            for library, campaigns in libraries.items():
                total_reached = 0
                total_triggered = 0
                var_reached = 0
                var_triggered = 0
                for campaignNum, result in campaigns.items():
                    total_reached = total_reached + len(result[0])
                    total_triggered = total_triggered + len(result[1])

                meanR = total_reached / number_of_campaigns[fuzzer][library]
                meanT = total_triggered / number_of_campaigns[fuzzer][library]

                for campaignNum, result in campaigns.items():
                    var_reached = var_reached + pow((len(result[0]) - meanR), 2)
                    var_triggered = var_triggered + pow((len(result[1]) - meanT), 2)

                mean_deviation_reached[fuzzer][library] = (meanR, sqrt(var_reached / number_of_campaigns[fuzzer][library]))
                mean_deviation_triggered[fuzzer][library] = (meanT, sqrt(var_triggered / number_of_campaigns[fuzzer][library]))

        return mean_deviation_reached, mean_deviation_triggered

    def remove_non_triggered_bugs(self):
        """
        Some bugs are only reached and never triggered. This function removes all the data about the
        not-triggered bugs
        """
        d = self.combine_sublibrary_fuzz_results()
        for fuzzer, libraries in d.items():
            for library, campaigns in libraries.items():
                for campaignNum, result in campaigns.items():
                    d[fuzzer][library][campaignNum] = self.intersect_bug_id(result[0], result[1])
        return d



    def intersect_bug_id(self, reached_bugs, triggered_bugs):
        """
           Helper function for remove_non_triggered_bugs

        """
        intersected_reached_bugs = [r_bug for r_bug in reached_bugs if
                                    r_bug[0] in [t_bug[0] for t_bug in triggered_bugs]]
        return intersected_reached_bugs, triggered_bugs

    def get_number_of_campaigns_per_fuzzer_library(self):
        """
        Returns for each fuzzer and target pair, how many campaigns that were
        actually run.
        """
        d = self.combine_sublibrary_fuzz_results()
        number_of_campaings_per_fuzzer_library = {}
        for fuzzer, libraries in d.items():
            number_of_campaings_per_fuzzer_library[fuzzer] = {}
            for library_name, campaigns in libraries.items():
                number_of_campaings_per_fuzzer_library[fuzzer][library_name] = len(campaigns.keys())
        return number_of_campaings_per_fuzzer_library

    def get_time_to_trigger_per_bug(self):
        """
        For each fuzzer target pair, fills a dictionnary containing a bug_id (unique) as key and
        a list with all the trigger times of this precise bug. The size of the list gives also the number of times a bug
        was triggered out of all the campaigns.
        """
        d = self.remove_non_triggered_bugs()
        for fuzzer, libraries in d.items():
            for library, campaigns in libraries.items():
                num_trigger = {}
                for campaignNum, result in campaigns.items():
                    result[0].sort(key=lambda x: x[0])
                    result[1].sort(key=lambda x: x[0])
                    for x in range(len(result[0])):
                        bug_id = result[0][x][0]
                        num_trigger[bug_id] = num_trigger.get(bug_id, []) + [result[1][x][1]]
                d[fuzzer][library] = num_trigger
        return d

    def expected_time_to_bug_for_each_fuzzer(self):
        """
        Computes the expected time-to-trigger for each bug
        Handles also the aggregate time by

        """
        d = self.get_time_to_trigger_per_bug()
        number_of_campaings_per_fuzzer_library = self.get_number_of_campaigns_per_fuzzer_library()
        expected_time_to_bug = {}
        aggregate = {}
        library_bugs = {}
        for fuzzer, libraries in d.items():
            expected_time_to_bug[fuzzer] = {}
            for library_name, bugs in libraries.items():
                for bug_id, time in bugs.items():
                    library_bugs[bug_id] = library_name
                    aggregate[bug_id] = aggregate.get(bug_id, []) + time
                    expected_time_to_bug[fuzzer][bug_id] = self.compute_expected_time_to_bug(time,
                                                                                             number_of_campaings_per_fuzzer_library[
                                                                                                 fuzzer][library_name])
        df = DataFrame(number_of_campaings_per_fuzzer_library)
        df = df.transpose().sum()
        for bug_id, times in aggregate.items():
            aggregate[bug_id] = self.compute_expected_time_to_bug(times, df[library_bugs[bug_id]])
        return expected_time_to_bug, aggregate

    def compute_expected_time_to_bug(self, list_of_times, number_of_campaigns,):
        """
        Implements the expected time-to-trigger bug formula used in the magma paper

        Parameters
        ----------
        list_of_times (list of integer):
            For one bug

        number_of_campaigns (integer):
            Number of campaigns actually run

        """

        T =self.CAMPAIGN_DURATION  # Secs in 24h
        N_minus_M = number_of_campaigns - len(list_of_times)
        if N_minus_M != 0:
            lambda_t = math.log(number_of_campaigns / N_minus_M)
        else:
            lambda_t = 1
        expected_time_to_bug_in_seconds = (((len(list_of_times) * statistics.mean(list_of_times)) + N_minus_M * (
                T / lambda_t)) / number_of_campaigns)
        return expected_time_to_bug_in_seconds

    def boxplot_unique_bugs_reached_in_all_libraries(self):
        """
        For each library, plots a boxplot that contains for each fuzzer the number of unique bugs reached
        """
        reached_unique, triggered_unique = self.get_total_number_of_unique_bugs()
        triggered = DataFrame(triggered_unique)
        fig = plt.figure()
        fig.canvas.set_window_title("Repartition of unique bugs reached by all fuzzer in a tested libraries")
        triggered.boxplot(figsize=(0.34, 20))
        plt.title("Repartition of unique bugs reached by all fuzzer in a tested libraries")
        plt.savefig(os.path.join(self.path.plot_dir, "unique_bug_box.svg"), format="svg")

    def barplot_mean_and_variance_of_bugs_found_by_each_fuzzer(self):
        """
        For each fuzzer, plots for each target the mean number of bugs found by the fuzzer along with
        the standard deviation computed over X campaigns
        """
        reached, triggered = self.get_mean_and_deviation_of_number_of_triggered_bugs()
        df = DataFrame(triggered)
        variances = df.applymap(lambda x: x[1])
        means = df.applymap(lambda x: x[0])
        fig, ax = plt.subplots()

        means.plot.bar(width=0.8, yerr=variances, ax=ax, figsize=(9, 6))

        ax.legend(loc="upper left", bbox_to_anchor=(1,1))
        plt.ylabel('Number of Bugs Triggered')
        plt.xlabel('Targets')
        plt.xticks(rotation=0)
        plt.title("Mean number of bugs found by different fuzzers for each target library")
        plt.savefig(os.path.join(self.path.plot_dir, "mean_variance_bar.svg"), format="svg", bbox_inches="tight")
        plt.clf()

    def barplot_reached_vs_triggered_bugs_by_each_fuzzer_in_a_library(self):
        """
        For each library generates of plots where the number of reached and triggered bugs is represented as a bar for
        each fuzzer
        """
        reached_unique, triggered_unique = self.get_total_number_of_unique_bugs()
        triggered = DataFrame(triggered_unique).transpose()
        reached = DataFrame(reached_unique).transpose()
        for library in reached:
            df = DataFrame({'Reached': reached[library], 'Triggered': triggered[library]})
            df.plot.bar(figsize=(8, 6), rot=0)
            plt.title("Number of reached and triggered bugs in " + library + " by all fuzzers")
            # plt.show()
            plt.savefig(os.path.join(self.path.plot_dir, library + "_reached_and_triggered_bar.svg"), format="svg")
            plt.clf()

    def heat_map_expected_time_to_bug(self):
        """
        Represents the expected time to trigger bug as a heat map.
        """
        data, aggregate = self.expected_time_to_bug_for_each_fuzzer()
        fuzzer_order = self.get_fuzzer_from_most_to_less_triggered_bugs(data)
        data["aggregate"] = aggregate
        df = DataFrame(data)
        df.sort_values(by='aggregate', inplace=True)
        df = df.drop(labels='aggregate', axis=1)
        df = df[fuzzer_order]
        fuzzers = list(df.columns)
        bug_id = list(df.index)
        raw_data = np.array(df)

        fig, ax = plt.subplots(figsize=(10, 10))
        heat_map = sns.heatmap(raw_data, cmap='seismic',
                               annot=self.get_labeled_data(raw_data),
                               xticklabels=fuzzers,
                               yticklabels=bug_id,
                               fmt='s',
                               norm=colors.PowerNorm(gamma=0.32),
                               ax=ax)
        ticks = [20850, 41700, 83400, 166800]
        tick_labels = ["6h", "12h", "24h", "48h"]
        cbar = ax.collections[0].colorbar
        cbar.set_ticks(ticks)
        cbar.set_ticklabels(tick_labels)
        ax.patch.set(fill='True', color='darkgrey')
        ax.set_title("Exptected time-to-trigger-bug for each fuzzer", fontsize=20)
        ax.xaxis.tick_top()
        ax.xaxis.set_label_position('top')
        plt.yticks(rotation=0)
        plt.xlabel("Fuzzers")
        plt.ylabel("Bugs")
        plt.savefig(os.path.join(self.path.plot_dir, "expected_time_to_bug_heat.svg"), format="svg")
        plt.clf()

    def heat_map_aggregate(self):
        """
        Represents the aggregate times for each bugs as a heat map
        """
        fuzzers, aggregate = self.expected_time_to_bug_for_each_fuzzer()
        agg = {}
        agg["aggregate"] = aggregate
        aggregate = DataFrame(agg)
        aggregate.sort_values(by='aggregate', inplace=True)
        bug_id = list(aggregate.index)
        data = np.array(aggregate)
        labelled_data = []
        for time in data:
            labelled_data.append([self.generate_variable_label_units(time)])

        fig, ax = plt.subplots(figsize=(8, 7))

        heat_map = sns.heatmap(data, cmap="seismic", annot=labelled_data, yticklabels=bug_id,
                               xticklabels=["Aggregate time"], fmt='s', norm=colors.PowerNorm(gamma=0.17),
                               cbar_kws=dict(ticks=[83400]), ax=ax)
        ticks = [20850, 41700, 83400, 166800]
        tick_labels = ["6h", "12h", "24h", "48h"]
        cbar = ax.collections[0].colorbar
        cbar.set_ticks(ticks)
        cbar.set_ticklabels(tick_labels)
        ax.set_title("Aggregate time for each bug in hours", fontsize=20)
        plt.ylabel("Triggered Bugs")
        plt.savefig(os.path.join(self.path.plot_dir, "aggregate_time_per_bug.svg"), format="svg")
        plt.clf()

    def get_fuzzer_from_most_to_less_triggered_bugs(self, data):
        """
        Sorts the fuzzers by the most to less triggered bugs.
        This is used on the heat map to order the columns of the heat map
        """
        most_bugs = {}
        for fuzzers, bugs in data.items():
            most_bugs[fuzzers] = len(bugs)
        most_bugs = sorted(most_bugs.items(), key=lambda x: x[1], reverse=True)
        most_bugs = [fuzzer for fuzzer, num_bugs in most_bugs]
        return most_bugs

    def get_labeled_data(self, to_label):
        """
        Converts an 2D array of data to a 2D array of string labels
        This is used in the heat map to show the times on each cell
        """
        labelled_data = []
        for bug in range(len(to_label)):
            labelled_data.append([])
            for bug_time in range(len(to_label[bug])):
                if not self.is_nan(to_label[bug][bug_time]):
                    labelled_data[bug].append(self.get_variable_time_unit(to_label[bug][bug_time]))
                else:
                    labelled_data[bug].append(to_label[bug][bug_time])
        return labelled_data

        # This function takes a numpy 2D array

    def get_variable_time_unit(self, elem):
        """
        Helper function for get_labled_data. Allows a variable units of times, instead of representing everything in seconds or
        hours
        """
        if self.is_nan(elem):
            return elem
        elif elem < 60:
            return str(int(elem)) + " sec"
        elif elem < 3600:
            return str(int(elem / 60)) + " min"
        else:
            return str(int(elem / 3600)) + " h"

    def is_nan(self, x):
        """
        return true if x is nan else return false
        """
        return (x != x)


    def get_sig_data(self):
        metric = "triggered"
        sig_data = {
            fuzzer: {
                target: [len(set(
                    bug for program in t_data.values() for rid, r_data in program.items() if rid == run for bug in
                    r_data[metric])) for run in (str(x) for x in range(10))]
                for target, t_data in f_data.items()
            } for fuzzer, f_data in self.data.items()
        }
        return sig_data

    def get_benchmark_snapshot_df(self):
        df = DataFrame(columns=['fuzzer', 'target', 'bugs'])
        for fuzzer, f_data in self.get_sig_data().items():
            for target, t_data in f_data.items():
                for bugs in t_data:
                    df = df.append(pd.DataFrame({
                        'fuzzer': [fuzzer.replace("aflplusplus", "afl++").replace("honggfuzz", "hfuzz")],
                        'target': [target],
                        'bugs': [bugs]
                    }), ignore_index=True)
        return df

    def create_p_value_table(self, benchmark_snapshot_df,
                             statistical_test,
                             alternative="two-sided"):
        """Given a benchmark snapshot data frame and a statistical test function,
        returns a p-value table. The |alternative| parameter defines the alternative
        hypothesis to be tested. Use "two-sided" for two-tailed (default), and
        "greater" or "less" for one-tailed test.
        The p-value table is a square matrix where each row and column represents a
        fuzzer, and each cell contains the resulting p-value of the pairwise
        statistical test of the fuzzer in the row and column of the cell.
        """

        def test_pair(measurements_x, measurements_y):
            return statistical_test(measurements_x,
                                    measurements_y,
                                    alternative=alternative).pvalue

        groups = benchmark_snapshot_df.groupby('fuzzer')
        samples = groups['bugs'].apply(list)
        fuzzers = samples.index

        data = []
        for f_i in fuzzers:
            row = []
            for f_j in fuzzers:
                if f_i == f_j:
                    # TODO(lszekeres): With Pandas 1.0.0+, switch to:
                    # p_value = pd.NA
                    p_value = np.nan
                elif set(samples[f_i]) == set(samples[f_j]):
                    p_value = np.nan
                else:
                    p_value = test_pair(samples[f_i], samples[f_j])
                row.append(p_value)
            data.append(row)

        p_values = pd.DataFrame(data, index=fuzzers, columns=fuzzers)
        return p_values

    def two_sided_u_test(self, benchmark_snapshot_df):
        """Returns p-value table for two-tailed Mann-Whitney U test."""
        return self.create_p_value_table(benchmark_snapshot_df,
                                         ss.mannwhitneyu,
                                         alternative='two-sided')

    def heatmap_pvalue(self):
        libraries, _ = self.get_all_targets_and_fuzzers()
        ncols = 3
        nrows = (len(libraries) - 1) // ncols + 1
        df = self.get_benchmark_snapshot_df()
        fig, ax = plt.subplots(nrows=nrows, ncols=ncols, figsize=(ncols * 3, nrows * 3))
        g_data = df.groupby('target')
        for i, target in enumerate(g_data.groups):
            figx = i // ncols
            figy = i % ncols
            axes = ax[figx, figy]

            # if i != 0:
            #     axes.get_yaxis().set_visible(False)

            axes.set_title(target)
            p_values = self.two_sided_u_test(g_data.get_group(target))
            self.heatmap_plot(p_values, symmetric=False, axes=axes, labels=False, cbar_ax_bbox=[1, 0.4, 0.02, 0.2])

        for i in range(len(g_data.groups), ncols * nrows):
            figx = i // ncols
            figy = i % ncols
            fig.delaxes(ax[figx, figy])

        fig.tight_layout(pad=2.0)
        fig.savefig(os.path.join(self.path.plot_dir, 'signplot.svg'), bbox_inches="tight")

    def heatmap_plot(self, p_values, axes=None, symmetric=False, **kwargs):
        """Draws heatmap plot for visualizing statistical test results.
        If |symmetric| is enabled, it masks out the upper triangle of the
        p-value table (as it is redundant with the lower triangle).
        """
        if symmetric:
            mask = np.zeros_like(p_values)
            mask[np.triu_indices_from(p_values)] = True
        heatmap_args = {
            'linewidths': 0.5,
            'linecolor': '0.5',
            'clip_on': False,
            'square': True,
            'cbar_ax_bbox': [0.85, 0.35, 0.04, 0.3],
            'mask': mask if symmetric else None,
        }
        heatmap_args.update(kwargs)
        return sp.sign_plot(p_values, ax=axes, **heatmap_args)

    def get_list_of_all_bugs(self, fuzzer, library):
        '''
        Get all bugs and their reached and triggered time

        Parameters
        ----------
        fuzzer (string):
            From which fuzzer

        library_name (string):
            From which library
        '''

        reached_map = {}
        triggered_map = {}

        for value in self.data[fuzzer][library].values():
            for kv, uv in value.items():
                for k, u in uv.items():
                    if not k in (self.REACHED, self.TRIGGERED):
                        continue
                    for bug, time in u.items():
                        if k == self.REACHED:
                            if bug in reached_map:
                                reached_map[bug].append(time)
                            else:
                                reached_map[bug] = [time]
                        elif k == self.TRIGGERED:
                            if bug in triggered_map:
                                triggered_map[bug].append(time)
                            else:
                                triggered_map[bug] = [time]
        return reached_map, triggered_map

    def box_plot(self, dictionary, fuzzer, library, metric):
        '''
        Create box plot graph

        Parameters
        ----------
        dictionary (string):
            From which fuzzer

        fuzzer (string):
            From which fuzzer

        library (string):
            From which library

        metric (string):
            From which metric
        '''

        df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in dictionary.items()]))

        # We increase the width so smaller boxes can be seen
        boxprops = dict(linestyle='-', linewidth=2, color='k')
        df.boxplot(figsize=(12, 10), boxprops=boxprops, vert=False)

        plt.title(metric + ". Fuzzer: " + fuzzer + ". Library:" + library)
        plt.ylabel("Bug Number")
        plt.xlabel("Time (seconds)")
        plt.ylim(bottom=0)

        plt.savefig(self.path.plot_dir + "/" + fuzzer + "_" + library + "_" + metric + "_box.svg", format="svg", bbox_inches="tight")
        plt.close()

    def generate_plots_for_fuzzer(self):
        '''
        Function to generate the different plots for the fuzzer pages
        '''

        libraries, fuzzers = self.get_all_targets_and_fuzzers()
        for fuzzer in fuzzers:
            for library in libraries:
                r, t = self.get_list_of_all_bugs(fuzzer, library)

                plt.clf()
                self.box_plot(r, fuzzer, library, self.REACHED)
                plt.clf()
                self.box_plot(t, fuzzer, library, self.TRIGGERED)
                plt.clf()

    def get_minimum_ttb(self, fuzzer, library, bug, campaign, metric):
        '''
        Get minimum time to be reached for a fuzzer, a library, a bug,
        a campaign and a metric

        Parameters
        ----------
        fuzzer (string):
            From which fuzzer

        library (string):
            From which library

        bug (string):
            From which bug

        campaign (string):
            From which campaign

        metric (string):
            From which metric
        '''

        samples = [np.nan]
        for program, p_data in self.data[fuzzer][library].items():
            r_data = p_data.get(campaign, np.nan)
            if (r_data is not np.nan):
                samples.append(r_data[metric].get(bug, np.nan))
        if np.all(np.isnan(samples)):
            return np.nan
        return np.nanmin(samples)

    def get_fuzzer_lib_bugs(self, fuzzer, library):
        '''
        Get all bugs for a fuzzer and a library

        Parameters
        ----------
        fuzzer (string):
            From which fuzzer

        library (string):
            From which library
        '''

        bugs = set()
        for p_data in self.data[fuzzer][library].values():
            for r_b_t in p_data.values():
                for b_t in r_b_t.values():
                    if type(b_t) is dict:
                        for bug in b_t.keys():
                            bugs.add(bug)
        return bugs

    def get_minimum_bugs(self, library, metric):
        '''
        Get all minimum time for all bugs for a fuzzer and a library

        Parameters
        ----------
        library (string):
            From which library

        metric (string):
            From which metric
        '''

        campaign_data = {}

        for fuzzer in self.data.keys():
            bugs = self.get_fuzzer_lib_bugs(fuzzer, library)
            campaign_dict = {
                campaign: {
                    bug: self.get_minimum_ttb(fuzzer, library, bug, campaign, metric)
                    for bug in bugs
                } for p_data in self.data[fuzzer][library].values()
                for campaign in p_data.keys()
            }
            campaign_data[fuzzer] = campaign_dict
        return campaign_data

    def get_step_value(self, series, x):
        serie = series[series.index <= x]
        if (serie.empty):
            return 0
        return serie.iloc[-1]

    def manage_nans(self, campaign_data):
        '''
        A function to manage nan values

        Parameters
        ----------
        campaign_data (dictionary):
            A dictionary of data
        '''

        plot_data = self.ddr()
        for fuzzer in self.data.keys():
            df = pd.DataFrame.from_dict(campaign_data[fuzzer], orient='index')
            for campaign in self.campaigns:
                if (campaign in df.index):
                    a = df.loc[campaign]
                    b = a[~np.isnan(a)]
                    plot_data[fuzzer][campaign] = b.value_counts().sort_index().cumsum()
        return plot_data

    def create_intervals(self, plot_data):
        '''
        A function to create all the necessary intervals

        Parameters
        ----------
        plot_data (dictionary):
            A dictionary of data
        '''

        aggplot_data = self.ddr()
        max_x = -1
        max_y = -1
        min_x = inf
        for fuzzer, data in plot_data.items():
            xvalues = sorted(set(index for campaign in data.values() for index in campaign.index))
            yvalues = [[self.get_step_value(campaign, x) for campaign in data.values()] for x in xvalues]

            cintervals = [1.96 * np.nanstd(i) / np.nanmean(i) for i in yvalues]
            ymeans = [np.nanmean(i) for i in yvalues]

            aggplot_data[fuzzer]["x"] = np.array(xvalues)
            aggplot_data[fuzzer]["y"] = np.array(ymeans)
            if (max(aggplot_data[fuzzer]["x"]) > max_x):
                max_x = max(aggplot_data[fuzzer]["x"])

            if (min(aggplot_data[fuzzer]["x"]) < min_x):
                min_x = min(aggplot_data[fuzzer]["x"])

            if (max(aggplot_data[fuzzer]["y"]) > max_y):
                max_y = max(aggplot_data[fuzzer]["y"])

            aggplot_data[fuzzer]["ci"] = np.array(cintervals)
        return aggplot_data, max_x, max_y, min_x

    # A function to draw the plots of data and setting different constants
    def draw_plot(self, aggplot_data, max_x, max_y, min_x, library):
        '''
        A function to create the line plots for all libraries

        Parameters
        ----------
        aggplot_data (dictionary):
            The data

        max_x (int):
            max value for x axis

        max_y (int):
            max value for y axis

        min_x (int):
            min value for x axis

        library (int):
            From which library
        '''

        fig, ax = plt.subplots(nrows=2, ncols=3, figsize=(15, 10))
        for i, fuzzer in enumerate(aggplot_data.keys()):
            figx = i // 3
            figy = i % 3
            axes = ax[figx, figy]

            x = aggplot_data[fuzzer]["x"]
            y = aggplot_data[fuzzer]["y"]
            ci = aggplot_data[fuzzer]["ci"]

            # axes.set_xscale('log')
            axes.step(x, y)
            axes.fill_between(x, (y - ci), (y + ci), color='b', alpha=.1)

            axes.set_title(fuzzer)
            axes.set_ylim((0, max_y + 5))
            axes.set_xlim((min_x, max_x + 5))
        plt.tight_layout()
        plt.savefig(os.path.join(self.path.plot_dir, library + "_unique_bug_line_plot.svg"), format="svg")
        plt.close()

    def line_plot_unique_bugs(self, metric):
        '''
        A function to create the line plots for all libraries

        Parameters
        ----------
        metric (string):
            Which metric to use
        '''

        libraries, fuzzers = self.get_all_targets_and_fuzzers()
        for library in libraries:
            campaign_data = self.get_minimum_bugs(library, metric)
            plot_data = self.manage_nans(campaign_data)
            aggplot_data, max_x, max_y, min_x = self.create_intervals(plot_data)
            self.draw_plot(aggplot_data, max_x, max_y, min_x, library)
