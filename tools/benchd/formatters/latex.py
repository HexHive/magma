from config import *

def timeformat(t):
    if type(t) is str:
        return t
    t //= 1000
    hours = t // 3600
    t = t % 3600
    minutes = t // 60
    seconds = t % 60

    if hours > 0:
        return f'{hours}h'
    elif minutes > 0:
        return f'{minutes}m'
    else:
        return f'{seconds}s'

def format_latex_tabular(fuzzers, order=None):
    try:
        _ = iter(order)
    except:
        order = fuzzers.keys()

    # determine max number of runs
    runs = max(int(r)
                for f in fuzzers
                for t in fuzzers[f]
                for p in fuzzers[f][t]
                for r in fuzzers[f][t][p])

    inf = r"\dinf"
    null = r"\dnull"
    rows = []
    for target, props in MAGMA_TARGETS.items():
        program = props["programs"][0][0]
        for b in props["bugs"]:
            bid = str(b).zfill(3)
            row = f'{bid},'
            for f in order:
                targets = fuzzers[f]
                if target in targets:
                    for i in range(runs):
                        if str(i) in fuzzers[f][target][program]:
                            row += (
                                f'{timeformat(fuzzers[f][target][program][str(i)]["reached"][b] or inf)},'
                                f'{timeformat(fuzzers[f][target][program][str(i)]["triggered"][b] or inf)},'
                            )
                        else:
                            row += f"{null}," * 2
                else:
                    row += f"{null}," * 2 * runs
            rows.append(row[:-1]) # do not print the last comma
    return "\n".join(sorted(rows))
