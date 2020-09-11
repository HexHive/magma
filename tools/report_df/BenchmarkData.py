import pandas as pd
from pandas import DataFrame
import numpy as np
import sys
import json
from collections import Mapping, Iterable

INDEX_NAMES = ['Fuzzer', 'Library','Program','Campaign','Metric','BugID']

#TODO add retrival of experiment infomation (Campaign duration)
class BenchmarkData:

    def __init__(self,filename):
        def flatten_key(k):
            flat = []
            if isinstance(k, Iterable) and not isinstance(k, str):
                for inner_value in k:
                    if isinstance(inner_value, Iterable) and not isinstance(k, str):
                        flat_value = flatten_key(inner_value)
                    else:
                        flat_value = (inner_value,)
                    flat.extend(flat_value)
            else:
                flat.append(k)
            return flat

        def flatten_dict(d):
            flat = {}
            for key, value in d.items():
                if isinstance(value, Mapping):
                    inner_flat = flatten_dict(value)
                    flat.update({
                        (key, *flatten_key(inner_key)): inner_value
                        for inner_key, inner_value in inner_flat.items()
                    })
                else:
                    # the value is stored in a list for use by the DataFrame
                    # as a single column
                    # TODO read dict as Series instead?
                    flat[key] = [value]
            return flat

        print("Load json")
        with open(filename) as f:
            json_data = json.load(f)

        df = DataFrame.from_dict(flatten_dict(json_data))
        df = df.transpose()
        # change column label from range to regular index
        df.rename(columns={0: 'Time'}, inplace=True)
        # change index names
        df.rename_axis(index=INDEX_NAMES, inplace=True)
        #Sorting for later performance gain
        self.df = df.sort_index()

        #extract campaign duration here from json

    def get_frame(self):
        return self.df

    def get_campaign_duration(self):
        # TODO read from file
        return 7 * 24 * 60 * 60

    def get_all_fuzzers(self):
        return list(self.df.index.get_level_values('Fuzzer').unique())

    def get_all_targets(self):
        return list(self.df.index.get_level_values('Library').unique())

    def get_all_metrics(self):
        return list(self.df.index.get_level_values('Metric').unique())
