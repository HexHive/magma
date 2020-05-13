from math import sqrt

import matplotlib.pyplot as plt
import pandas as pd
from pandas import DataFrame

import json  # TODO Delete
from Path import Path


class Plots:
    REACHED = "reached"
    TRIGGERED = "triggered"

    def __init__(self, data, path):
        self.data = data

    def generate(self):
        return

    def violinPlot(self, fuzzer):
        meanR, meanT = self.meanAndDeviationOfNumberOfBugsAcrossXCampaigns(10)

        print(meanR)
        df = DataFrame(meanR[fuzzer])
        fig, axes = plt.subplots()

        axes.violinplot(dataset=df)

        axes.set_title('')
        axes.yaxis.grid(True)
        axes.set_xlabel('')
        axes.set_ylabel('')

        plt.show()

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
                                        simplified_data[fuzzer][library][campaign][0].append(
                                            (reached_bugs, times))

                            elif conditions == self.TRIGGERED:
                                for triggered_bugs, times in self.data[fuzzer][library][sublibraries][campaign][
                                    conditions].items():
                                    if triggered_bugs not in [i[0] for i in
                                                              simplified_data[fuzzer][library][campaign][1]]:
                                        simplified_data[fuzzer][library][campaign][1].append(
                                            (triggered_bugs, times))

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
        d = self.combineSublibrariesFuzzerResults()
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

    def boxplot(self, data, title):
        fig = plt.figure()
        fig.canvas.set_window_title(title)
        data.boxplot(figsize=(0.34, 20))
        plt.title(title)
        # plt.savefig("test.svg", format="svg")

    def barplot(self, data, title):
        data.transpose().plot.bar()
        plt.title(title)
        # plt.savefig("test.svg", format="svg")

    def barplotReachedVsTriggeredBugsByFuzzersForALibrary(self, reached, triggered, library, title):
        df = DataFrame({'Reached': reached[library], 'Triggered': triggered[library]})
        df.plot.bar()
        plt.title(title)
        plt.savefig(library + ".svg", format="svg")

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

    def box_plot(self, dictionary):
        df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in dictionary.items()]))
        # df.to_html("name.html", index=True)
        df.boxplot()
        plt.show()
        # plt.savefig

    def bugs_plot_line(self, dictionnary):
        df = pd.DataFrame.from_dict(dictionnary)

        df = df.T
        df.plot(subplots=True)
        plt.show()

    def save_plot_tables(self, dictionnary, name):
        # Note that we use dtype to avoid having to deal with a pandas gotcha with floats and ints
        df = pd.DataFrame.from_dict(dictionnary, dtype='Int64')
        df = df.reindex(sorted(df.columns), axis=1)
        df.to_html(name)


# data = {}

# with open("../../../../../20200501_24h.json") as f:
#     data = json.load(f)


# plot = Plots(data, Path("to_deleleeeeeeetttee", "fucke222", "../WebPages/outputs/plots", "../WebPages/outputs/tables"))

    """
=======
# fuzzer_name = "moptafl"
# library_name = "poppler"
# reached_map_all, triggered_map_all = plot.get_all_bugs(fuzzer_name, library_name)
# reached_map, triggered_map = plot.get_bugs_for_driver(fuzzer_name, library_name,
#                                                       "pdf_fuzzer")

# r, t = plot.get_list_of_all_bugs(fuzzer_name, library_name)
# plot.bugs_plot_line(reached_map)
# plot.box_plot(r)

