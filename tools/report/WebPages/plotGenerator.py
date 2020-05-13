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
        df = pd.DataFrame(self.extractAllBugsWithNoTimeForEachLibraryFuzzerPair()).transpose()
        reached_unique, triggered_unique = self.uniqueBugs(df)
        for col in triggered_unique:
            triggered_unique[col] = triggered_unique[col].apply(lambda x: len(x))
            reached_unique[col] = reached_unique[col].apply(lambda x: len(x))
        # self.boxplot(reached_unique, "Repartition of unique bugs reached by all fuzzer in a tested libraries")
        for librarie in df:
            self.barplotReachedVsTriggeredBugsByFuzzersForALibrary(reached_unique, triggered_unique, librarie,
                                                                   "Reached and Triggered unique bug count for each fuzzer in " + librarie)

    def extractAllBugsWithNoTimeForEachLibraryFuzzerPair(self):
        simplified_data = {}
        for fuzzer in self.data:
            simplified_data[fuzzer] = {}
            for librarie in self.data[fuzzer]:
                simplified_data[fuzzer][librarie] = ([], [])
                for sublibraries in self.data[fuzzer][librarie]:
                    for campaign in self.data[fuzzer][librarie][sublibraries]:
                        for conditions in self.data[fuzzer][librarie][sublibraries][campaign]:
                            if conditions == self.REACHED:
                                for reached_bugs in self.data[fuzzer][librarie][sublibraries][campaign][conditions]:
                                    simplified_data[fuzzer][librarie][0].append(reached_bugs)

                            elif conditions == self.TRIGGERED:
                                for triggered_bugs in self.data[fuzzer][librarie][sublibraries][campaign][conditions]:
                                    simplified_data[fuzzer][librarie][1].append(triggered_bugs)
        return simplified_data

    def nonUniqueBugs(self, data):
        reached = data.copy()
        triggered = data.copy()
        for col in data:
            reached[col] = reached[col].apply(lambda x: x[0])
            triggered[col] = triggered[col].apply(lambda x: x[1])
        return reached, triggered

    # ...

    def uniqueBugs(self, data):
        reached = data.copy()
        triggered = data.copy()
        for col in data:
            reached[col] = reached[col].apply(lambda x: set(x[0]))
            triggered[col] = triggered[col].apply(lambda x: set(x[1]))
        return reached, triggered

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

# fuzzer_name = "moptafl"
# library_name = "poppler"
# reached_map_all, triggered_map_all = plot.get_all_bugs(fuzzer_name, library_name)
# reached_map, triggered_map = plot.get_bugs_for_driver(fuzzer_name, library_name,
#                                                       "pdf_fuzzer")

r, t = plot.get_list_of_all_bugs(fuzzer_name, library_name)
# plot.bugs_plot_line(reached_map)
# plot.box_plot(r)
