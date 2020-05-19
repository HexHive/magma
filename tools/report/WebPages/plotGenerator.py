import matplotlib.pyplot as plt
import pandas as pd
from pandas import DataFrame
from math import sqrt
import seaborn as sns
import statistics
import math
import numpy as np
import json  # TODO Delete
from Path import Path


class Plots:
    REACHED = "reached"
    TRIGGERED = "triggered"

    def __init__(self, data, path):
        self.data = data
        self.path = path

    def generate(self):

        # self.barplot_mean_and_variance_of_bugs_found()
        # self.barplot_reached_vs_triggered_bugs_by_each_fuzzer_in_a_library()
        # self.heat_map_expected_time_to_bug()
        self.barplot_mean_and_variance_of_bugs_found_by_each_fuzzer()

    def combineSublibrarysFuzzerResults(self):
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

    def totalNumberofUniqueBugsAcrossXCampaigns(self):
        d = self.combineSublibrarysFuzzerResults()

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

    def meanAndDeviationOfNumberOfBugsAcrossXCampaigns(self, numberOfCampaings):
        d = self.combineSublibrarysFuzzerResults()
        mean_deviation_reached = d.copy()
        mean_deviation_triggered = d.copy()
        for fuzzer, libraries in d.items():
            for library, campaigns in libraries.items():
                total_reached = 0
                total_triggered = 0
                var_reached = 0
                var_triggered = 0
                for campaignNum, result in campaigns.items():
                    total_reached = total_reached + len(result[0])
                    total_triggered = total_triggered + len(result[1])

                meanR = total_reached / numberOfCampaings
                meanT = total_triggered / numberOfCampaings

                for campaignNum, result in campaigns.items():
                    var_reached = var_reached + pow((len(result[0]) - meanR), 2)
                    var_triggered = var_triggered + pow((len(result[1]) - meanT), 2)

                mean_deviation_reached[fuzzer][library] = (meanR, sqrt(var_reached / numberOfCampaings))
                mean_deviation_triggered[fuzzer][library] = (meanT, sqrt(var_triggered / numberOfCampaings))

        return mean_deviation_reached, mean_deviation_triggered

    def remove_non_triggered_bugs(self):
        d = self.combineSublibrarysFuzzerResults()
        for fuzzer, libraries in d.items():
            for library, campaigns in libraries.items():
                for campaignNum, result in campaigns.items():
                    d[fuzzer][library][campaignNum] = self.intersect_bug_id(result[0], result[1])

        return d

    def intersect_bug_id(self, reached_bugs, triggered_bugs):
        intersected_reached_bugs = [r_bug for r_bug in reached_bugs if
                                    r_bug[0] in [t_bug[0] for t_bug in triggered_bugs]]
        return intersected_reached_bugs, triggered_bugs

    def time_to_trigger_per_bug(self):
        d = self.remove_non_triggered_bugs()

        for fuzzer, libraries in d.items():
            for library, campaigns in libraries.items():
                num_trigger = {}
                for campaignNum, result in campaigns.items():
                    result[0].sort(key=lambda x: x[0])
                    result[1].sort(key=lambda x: x[0])
                    for x in range(len(result[0])):
                        bug_id = result[0][x][0]
                        num_trigger[bug_id] = num_trigger.get(bug_id, []) + [result[1][x][1] - result[0][x][1]]
                d[fuzzer][library] = num_trigger
        return d

    def expected_time_to_bug_for_each_fuzzer(self, num_campaigns, campaign_duration):
        d = self.time_to_trigger_per_bug()
        expected_time_to_bug = {}
        aggregate = {}
        for fuzzer, library in d.items():
            expected_time_to_bug[fuzzer] = {}
            for bugs in library.values():
                for bug_id, time in bugs.items():
                    aggregate[bug_id] = aggregate.get(bug_id, []) + time
                    # ln(N/N-M)
                    expected_time_to_bug[fuzzer][bug_id] = self.compute_expected_time_to_bug(time, num_campaigns,
                                                                                             campaign_duration)

        number_of_fuzzers = len(list(d.keys()))
        for bug_id, times in aggregate.items():
            aggregate[bug_id] = self.compute_expected_time_to_bug(times, num_campaigns * number_of_fuzzers,
                                                                  campaign_duration)
        return expected_time_to_bug, aggregate

    def compute_expected_time_to_bug(self, list_of_times, num_campaigns, campaign_duration):
        T = campaign_duration  # Secs in 24h
        N_minus_M = num_campaigns - len(list_of_times)
        if N_minus_M is not 0:
            lambda_t = math.log(num_campaigns / N_minus_M)
        else:
            lambda_t = 1
        expected_time_to_bug_in_seconds = (((len(list_of_times) * statistics.mean(list_of_times)) + N_minus_M * (
                    T / lambda_t)) / num_campaigns)
        return expected_time_to_bug_in_seconds / 3600

    def boxplot_unique_bugs_reached_in_all_libraries(self):
        reached_unique, triggered_unique = self.totalNumberofUniqueBugsAcrossXCampaigns()
        triggered = DataFrame(triggered_unique)
        fig = plt.figure()
        triggered.boxplot(figsize=(0.34, 20))
        plt.title("Repartition of unique bugs reached by all fuzzer in a tested libraries")
        plt.show()
        plt.savefig("unique_reached_bugs_box.svg", format="svg")

    def barplot_mean_and_variance_of_bugs_found_by_each_fuzzer(self):
        reached, triggered = self.meanAndDeviationOfNumberOfBugsAcrossXCampaigns(10)
        for fuzzer, libData in triggered.items():
            mean_values = []
            libraries = []
            variance = []
            for lib, meanVar in libData.items():
                mean_values.append(meanVar[0])
                variance.append(pow(meanVar[1], 2))
                libraries.append(lib)
            x_pos = list(range(len(libraries)))
            plt.bar(x_pos, mean_values, yerr=variance, align='center', alpha=0.5)
            plt.grid()
            plt.ylabel('Number of Bugs Triggered')
            plt.xticks(x_pos, libraries)
            plt.title("Mean number of bugs found by " + fuzzer + " for each target library")
            plt.show()
            plt.savefig("mean_var_" + fuzzer + "_bar.svg", format="svg")

    def barplot_reached_vs_triggered_bugs_by_each_fuzzer_in_a_library(self):
        reached_unique, triggered_unique = self.totalNumberofUniqueBugsAcrossXCampaigns()
        triggered = DataFrame(triggered_unique).transpose()
        reached = DataFrame(reached_unique).transpose()
        for library in reached:
            df = DataFrame({'Reached': reached[library], 'Triggered': triggered[library]})
            df.plot.bar(figsize=(8, 6), rot=0)
            plt.title("Number of reached and triggered bugs in " + library + " by all fuzzers")
            plt.show()
            plt.savefig(library+"_bar.svg", format="svg")

    def heat_map_expected_time_to_bug(self):
        data, aggregate = self.expected_time_to_bug_for_each_fuzzer(10, 83400)
        data["aggregate"] = aggregate
        data = DataFrame(data)
        data.sort_values(by='aggregate', inplace=True)
        data = data.drop(labels='aggregate', axis=1)
        fuzzers = list(data.columns)
        bug_id = list(data.index)
        data = np.array(data)
        fig, ax = plt.subplots(figsize=(10, 10))
        sns.heatmap(data, cmap="YlGnBu", annot=True, xticklabels=fuzzers, yticklabels=bug_id, fmt='.1f',
                               ax=ax)
        ax.set_title("Exptected time-to-trigger-bug for each fuzzer in hours", fontsize=20)
        plt.show()
        plt.savefig("Expected_time_to_bug_heat.svg", format="svg")

    def heat_map_aggregate(self):
        fuzzers, aggregate = self.expected_time_to_bug_for_each_fuzzer(10, 83400)
        data = DataFrame(fuzzers)
        agg = {}
        agg["aggregate"] = aggregate
        aggregate = DataFrame(agg)
        aggregate.sort_values(by='aggregate', inplace=True)
        bug_id = list(data.index)
        data = np.array(aggregate)
        print(data)
        fig, ax = plt.subplots(figsize=(8, 7))
        heat_map = sns.heatmap(data, cmap="YlGnBu", annot=True, yticklabels=bug_id, xticklabels=["Aggregate time"],
                               fmt='.1f', ax=ax)
        ax.set_title("Aggregate time for each bug in hours", fontsize=20)
        plt.ylabel("Triggered Bugs")
        plt.show()
        plt.savefig("Aggregate_time_per_bug_heat.svg", format="svg")



    def add_to_map_reach(self, bug, time, reached_map):
        if bug in reached_map:
            reached_map[bug].append(time)
        else:
            reached_map[bug] = [time]

    def merge(self, map_one, map_two):
        # Merge map {campaign_number -> {BUG_NAME: [204, 330, 439]}}
        for key, v in map_two.items():
            if key in map_one:
                for bug, time in v.items():
                    if bug in map_one[key]:
                        map_one[key][bug].append(time)
                    else:
                        map_one[key][bug] = [time]
            else:
                for bug, time in v.items():
                    map_one[key] = {bug: [time]}

    def get_data(self, bug_map):
        reached_map_list = {}

        for key, value in bug_map.items():
            for bug, time in value.items():
                if bug in reached_map_list:
                    reached_map_list[bug].append(time)
                else:
                    reached_map_list[bug] = [time]

        return reached_map_list

    def get_all_bugs(self, fuzzer_name, library_name):
        reached_map = {}
        triggered_map = {}

        for driver in self.data[fuzzer_name][library_name].keys():
            reached_map_list, triggered_map_list = self.get_bugs_for_driver(fuzzer_name, library_name, driver)
            self.merge(reached_map, reached_map_list)
            self.merge(triggered_map, triggered_map_list)

        return reached_map, triggered_map

    def get_bugs_for_driver(self, fuzzer_name, library_name, driver):
        reached_map = {}
        triggered_map = {}

        for key, value in self.data[fuzzer_name][library_name][driver].items():
            for kv, uv in value.items():
                if kv == self.REACHED:
                    reached_map[key] = uv
                elif kv == self.TRIGGERED:
                    triggered_map[key] = uv

        return reached_map, triggered_map

    def get_list_of_all_bugs(self, fuzzer_name, library_name):
        reached_map = {}
        triggered_map = {}

        for value in self.data[fuzzer_name][library_name].values():
            for kv, uv in value.items():
                for k, u in uv.items():
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

    def get_list_of_all_bugs_time(self, fuzzer_name, library_name):
        reached_map = {}
        triggered_map = {}

        for value in self.data[fuzzer_name][library_name].values():
            for campaign, uv in value.items():
                reached_map[campaign] = {}
                triggered_map[campaign] = {}
                for k, u in uv.items():
                    for bug, time in u.items():
                        if k == self.REACHED:
                            if time in reached_map[campaign]:
                                reached_map[campaign][time] += 1
                            else:
                                reached_map[campaign][time] = 1
                        elif k == self.TRIGGERED:
                            if time in triggered_map[campaign]:
                                triggered_map[campaign][time] += 1
                            else:
                                triggered_map[campaign][time] = 1
        return reached_map, triggered_map

    def to_html(self, dataframe, output_name):
        df = pd.DataFrame(dataframe)
        df.to_html(self.path.tables_dir + "/" + output_name + ".html", index=True)

    def to_html_without_decimal(self, dataframe, output_name):
        df = pd.DataFrame(dataframe)
        df = df.astype('Int64').astype(str).replace("<NA>", "")
        df.to_html(self.path.tables_dir + "/" + output_name + ".html", index=True)

    def line_plot_bug_number(self, dictionary, output_name):
        df = pd.DataFrame(dictionary)

        df = df.T
        df = df.reindex(sorted(df.columns), axis=1)
        df = df.T

        df.interpolate(method='linear').plot(subplots=True, marker='o')
        self.to_html_without_decimal(df, output_name)
        # plt.savefig("test.svg", format="svg")

    def box_plot_bug_number(self, dictionary, output_name):
        df = pd.DataFrame(dictionary)
        df = df.T
        df = df.reindex(sorted(df.columns), axis=1)
        df.plot(marker='o')
        self.to_html_without_decimal(df, output_name)
        # plt.savefig("test.svg", format="svg")

    def box_plot(self, dictionary, output_name):
        df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in dictionary.items()]))
        df.boxplot()
        self.to_html_without_decimal(df, output_name)
        # plt.savefig("test.svg", format="svg")

    def bugs_plot_line(self, dictionnary, output_name):
        df = pd.DataFrame.from_dict(dictionnary)

        df = df.T
        df.plot(subplots=True, marker='o')
        self.to_html_without_decimal(df, output_name)
        # df.to_html("name.html", index=True, na_rep="")
        # plt.savefig("test.svg", format="svg")

    def save_plot_tables(self, dictionnary, output_name):
        # Note that we use dtype to avoid having to deal with a pandas gotcha with floats and ints
        df = pd.DataFrame.from_dict(dictionnary)
        df = df.reindex(sorted(df.columns), axis=1)
        # df.to_html("name.html", index=True, na_rep="")
        # plt.savefig("test.svg", format="svg")


data = {}

with open("../../../../../20200501_24h.json") as f:
    data = json.load(f)

plot = Plots(data, Path("random_delete", "random_delete_2",
                        "../WebPages/outputs/tables", "../WebPages/outputs/plots"))

fuzzer_name = "moptafl"
library_name = "poppler"
# library_name = "libpng"
# library_name = "libtiff"
# library_name = "libxml2"
# library_name = "sqlite3"
# library_name = "php"
# reached_map_all, triggered_map_all = plot.get_all_bugs(fuzzer_name, library_name)
# reached_map, triggered_map = plot.get_bugs_for_driver(fuzzer_name, library_name,
#                                                      "pdf_fuzzer")

r, t = plot.get_list_of_all_bugs_time(fuzzer_name, library_name)

# r, t = plot.get_list_of_all_bugs(fuzzer_name, library_name)
# plot.bugs_plot_line(reached_map)
# plot.box_plot(r)

plot.line_plot_bug_number(r, fuzzer_name + "_" + library_name)
# plot.line_plot_bug_number(t)
