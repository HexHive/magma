import matplotlib.pyplot as plt
import pandas as pd
from pandas import DataFrame


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
    reached_map_all, triggered_map_all = self.get_all_bugs(fuzzer_name, library_name)
    reached = []
    triggered = []

    for key, value in reached_map_all:
        reached.append(key)

    for key, value in triggered_map_all:
        triggered.append(key)

    return reached, triggered


fuzzer_name = "moptafl"
library_name = "poppler"
reached_map_all, triggered_map_all = get_all_bugs(fuzzer_name, library_name)

reached_map, triggered_map = get_bugs_for_driver(fuzzer_name, library_name,
                                                 "pdf_fuzzer")

reached_map_list = get_data(reached_map)

# plt.savefig("test.svg", format="svg")
