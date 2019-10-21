import pandas as pd
import os

def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]

out_dir = "/root/campaigns"

target_props = {
    "libpng16": {
        "bugs": [1,2,3,4,5,7,8],
        "programs": [("readpng", "@@")]
    },
    "libtiff4": {
        "bugs": [9,10,11,12,13,14,15,16,17,18,19,20,21,22],
        "programs": [("tiffcp", "-i @@ /dev/null")]
    },
    "libxml2": {
        "bugs": [23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41],
        "programs": [("xmllint", "--valid --oldxml10 --push --memory @@")]
    },
    "poppler": {
        "bugs": [42,43,45,46,47,48,49,50,51,52],
        "programs": [("pdftoppm", "-mono -cropbox @@"), ("pdfimages", "@@ /tmp/out")]
    }
}

runs = 0
fuzzers = {}
for root, dirs, files in walklevel(out_dir, level=1):
    if not bool(fuzzers):
        fuzzers = fuzzers.fromkeys(dirs)
        continue

    f = os.path.basename(root)
    campaigns = [dir.split('_') for dir in dirs]
    campaigns = [
        {
            "fuzzer": c[0],
            "target": c[1],
            "program": c[2],
            "run": c[3],
            "cid": c[4]
        } for c in campaigns]

    targets = set(c["target"] for c in campaigns)
    fuzzers[f] = dict.fromkeys(targets)
    for t in fuzzers[f]:
        fuzzers[f][t] = dict.fromkeys(set(c["program"] for c in campaigns if c["target"] == t))
        for p in fuzzers[f][t]:
            fuzzers[f][t][p] = dict.fromkeys(set(c["run"] for c in campaigns if c["target"] == t and c["program"] == p))
            for r in fuzzers[f][t][p]:
                # save the number of runs for later use
                if (int(r)+1) > runs:
                    runs = int(r)+1

                fuzzer, cid = next((c["fuzzer"],c["cid"]) for c in campaigns
                                   if c["target"] == t and c["program"] == p and c["run"] == r)
                c_path = os.path.join(root, f"{fuzzer}_{t}_{p}_{r}_{cid}")
                m_path = os.path.join(c_path, "monitor.txt")
                df = pd.read_csv(m_path, sep='\t', header=0, index_col="TIME")
                fuzzers[f][t][p][r] = {
                    "path": c_path,
                    "df": df,
                    "reached": dict.fromkeys(target_props[t]["bugs"]),
                    "triggered": dict.fromkeys(target_props[t]["bugs"])
                }

                for bug in target_props[t]["bugs"]:
                    bid = str(bug).zfill(3)
                    reached = df[df[f"{bid}_R"] > 0]
                    if not reached.empty:
                        fuzzers[f][t][p][r]["reached"][bug] = reached.index[0]
                    triggered = df[df[f"{bid}_T"] > 0]
                    if not triggered.empty:
                        fuzzers[f][t][p][r]["triggered"][bug] = triggered.index[0]

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

ordered = ["afl", "aflfast", "moptafl", "fairfuzz", "honggfuzz", "angora"]

inf = r"\dinf"
for target, props in target_props.items():
    program = props["programs"][0][0]
    for b in props["bugs"]:
        bid = str(b).zfill(3)
        row = f'{bid},'
        for f in ordered:
            targets = fuzzers[f]
            if target in targets:
                for i in range(runs):
                    row += (
                        f'{timeformat(fuzzers[f][target][program][str(i)]["reached"][b] or inf)},'
                        f'{timeformat(fuzzers[f][target][program][str(i)]["triggered"][b] or inf)},'
                    )
            else:
                row += "\dnull," * 2 * runs
        print(row[:-1]) # do not print the last comma
