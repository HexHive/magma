import pandas as pd
from pandas import DataFrame
import numpy as np
import sys
import json
from collections import Mapping, Iterable

INDEX_NAMES = ['Fuzzer', 'Target','Program','Campaign','Metric','BugID']

#TODO add retrival of experiment infomation (Campaign duration)
class BenchmarkData:

    def __init__(self,filename, **kwargs):
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

        def update_dict(d, u):
            for k, v in u.items():
                if isinstance(v, Mapping):
                    d[k] = update_dict(d.get(k, {}), v)
                else:
                    d[k] = v
            return d

        print("Load json")
        with open(filename) as f:
            json_data = json.load(f)

        # include any custom configuration into the json object
        update_dict(json_data, kwargs)

        # load experiment results
        df = DataFrame.from_dict(flatten_dict(json_data['results']))
        df = df.transpose()
        # change column label from range to regular index
        df.rename(columns={0: 'Time'}, inplace=True)
        # change index names
        df.rename_axis(index=INDEX_NAMES, inplace=True)
        #Sorting for later performance gain
        self._df = df.sort_index()

        # save configuration parameters
        self._config = json_data.get('config', {})
        self._version = json_data.get('version', 'v1.0')

    @property
    def frame(self):
        return self._df

    @property
    def duration(self):
        return self._config.get('duration', 24 * 60 * 60)

    @property
    def trials(self):
        return self._config.get('trials', 10)

    @property
    def version(self):
        return self._version

    def get_all_fuzzers(self):
        return list(self._df.index.get_level_values('Fuzzer').unique())

    def get_all_targets(self):
        return list(self._df.index.get_level_values('Target').unique())

    def get_all_metrics(self):
        return list(self._df.index.get_level_values('Metric').unique())
