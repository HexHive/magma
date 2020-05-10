import json
import matplotlib.pyplot as plt
import pandas as pd
from pandas import DataFrame


class GeneratePlots:

    def __init__(self, file):
        '''
        Parameters
        ----------
        file (string):
            The name of the json file containing the data
        '''

        self.file = file


def transformDataIntoNonUniqueReachedAndTriggeredBugs(data):
    reached = data.copy()
    triggered = data.copy()
    for col in data:
        reached[col] = reached[col].apply(lambda x: x[0])
        triggered[col] = triggered[col].apply(lambda x: x[1])
    return reached, triggered


# ...

def transformDataIntoUniqueReachedAndTriggeredBugs(data):
    reached = data.copy()
    triggered = data.copy()
    for col in data:
        reached[col] = reached[col].apply(lambda x: set(x[0]))
        triggered[col] = triggered[col].apply(lambda x: set(x[1]))
    return reached, triggered


def boxplot(data, title):
    fig = plt.figure()
    fig.canvas.set_window_title(title)
    data.boxplot(figsize=(0.34, 20))
    plt.title(title)
    # plt.savefig("test.svg", format="svg")


def barplot(data, title):
    data.transpose().plot.bar()
    plt.title(title)
    # plt.savefig("test.svg", format="svg")


def barplotReachedVsTriggeredForALibrary(reached, triggered, library, title):
    # fig = plt.figure()
    # fig.canvas.set_window_title(title)
    df = DataFrame({'Reached': reached[library], 'Triggered': triggered[library]})
    df.plot.bar()
    plt.title(title)
    # plt.savefig("test.svg", format="svg")


def transformJsonToContainAListOfReachedAndTriggeredBugs(json_string):
    updated_json = {}
    with open(json_string) as campaign_results:
        data = json.load(campaign_results)
        for fuzzer in data:
            updated_json[fuzzer] = {}
            for librarie in data[fuzzer]:
                updated_json[fuzzer][librarie] = ([], [])
                for sublibraries in data[fuzzer][librarie]:
                    for campaign in data[fuzzer][librarie][sublibraries]:
                        for conditions in data[fuzzer][librarie][sublibraries][campaign]:
                            if conditions == 'reached':
                                for reached_bugs in data[fuzzer][librarie][sublibraries][campaign][conditions]:
                                    updated_json[fuzzer][librarie][0].append(reached_bugs)

                            elif conditions == 'triggered':
                                for triggered_bugs in data[fuzzer][librarie][sublibraries][campaign][conditions]:
                                    updated_json[fuzzer][librarie][1].append(triggered_bugs)
    return updated_json


data = transformJsonToContainAListOfReachedAndTriggeredBugs('20200501_24h.json')
df = pd.DataFrame(data).transpose()
reached_non_unique, triggered_non_unique = transformDataIntoNonUniqueReachedAndTriggeredBugs(df)
reached_unique, triggered_unique = transformDataIntoUniqueReachedAndTriggeredBugs(df)
for col in triggered_non_unique:
    triggered_non_unique[col] = triggered_non_unique[col].apply(lambda x: len(x))
    reached_non_unique[col] = reached_non_unique[col].apply(lambda x: len(x))
    triggered_unique[col] = triggered_unique[col].apply(lambda x: len(x))
    reached_unique[col] = reached_unique[col].apply(lambda x: len(x))

print(reached_unique)
boxplot(reached_unique, "Repartition of unique bugs reached by all fuzzer in a tested libraries")
barplotReachedVsTriggeredForALibrary(reached_unique, triggered_unique, 'libpng',
                                     "Reached and Triggered unique bug count for each fuzzer in libpng")
plt.show()

# ==============================================================================
# ==============================================================================
# ==============================================================================

json_data = "20200501_24h.json"

data = ""
with open(json_data) as f:
    data = json.load(f)

# for i in data:
#     print(i)

# print(data["moptafl"]["poppler"])

reached = "reached"
triggered = "triggered"


def add_to_map_reach(bug, time, reached_map):
    if bug in reached_map:
        reached_map[bug].append(time)
    else:
        reached_map[bug] = [time]


def merge(map_one, map_two):
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


def get_data(bug_map):
    reached_map_list = {}

    for key, value in bug_map.items():
        for bug, time in value.items():
            if bug in reached_map_list:
                reached_map_list[bug].append(time)
            else:
                reached_map_list[bug] = [time]

    return reached_map_list


def get_all_bugs(fuzzer_name, library_name):
    reached_map = {}
    triggered_map = {}

    for driver in data[fuzzer_name][library_name].keys():
        reached_map_list, triggered_map_list = get_bugs_for_driver(fuzzer_name, library_name, driver)
        merge(reached_map, reached_map_list)
        merge(triggered_map, triggered_map_list)

    return (reached_map, triggered_map)


def get_bugs_for_driver(fuzzer_name, library_name, driver):
    reached_map = {}
    triggered_map = {}

    for key, value in data[fuzzer_name][library_name][driver].items():
        for kv, uv in value.items():
            if (kv == reached):
                reached_map[key] = uv
            elif (kv == triggered):
                triggered_map[key] = uv

    return (reached_map, triggered_map)


fuzzer_name = "moptafl"
library_name = "poppler"
reached_map_all, triggered_map_all = get_all_bugs(fuzzer_name, library_name)

reached_map, triggered_map = get_bugs_for_driver(fuzzer_name, library_name,
                                                 "pdf_fuzzer")

reached_map_list = get_data(reached_map)

plt.savefig("test.svg", format="svg")
