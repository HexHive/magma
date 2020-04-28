import pandas as pd
import bs4 as bs
import re

import os

XML_PARSER = "lxml"
YES_BOX = "&#10003;"
NO_BOX = "&#10007;"
PORTED = "Ported"


def html_to_csv(name, output):
    links = []
    f = open(name, "r")
    soup = bs.BeautifulSoup(f, XML_PARSER)
    f.close()
    links = soup.find_all("a")
    cleanSoup = ""
    for link in links:
        cleanSoup = str(soup).replace(str(link), link["href"])

    for i, df in enumerate(pd.read_html(str(cleanSoup))):
        df.to_csv("%s_" + output % i, index=False)


def linkify(entry):
    if(isinstance(entry, str)):
        https = re.findall(r"http[^\s]+", entry)
        for h in https:
            entry = entry.replace(h, "<a href=\"" + h + "\">link</a>")
    return entry


def csv_to_html(name, output):
    csv = pd.read_csv(name, sep=',')
    for c in csv.columns.values:
        csv[c] = csv[c].apply(linkify)
    csv[PORTED] = csv[PORTED].apply(lambda x: YES_BOX if x
                                    else NO_BOX)

    # Making sure that tick boxes are centered in the table
    # Formating the ported column
    formatter = {PORTED: lambda x: "<div align=\"center\">" + x + "</div>"}

    # na_rep="", because we want to avoid having literal "NaN"
    # values in the tables when converting to html. So we replace it with empty
    # strings

    # index=False, so that we don't number the html lines
    # escape=False because else it will interpret "<" as "&lt;"
    # and ">" as "&gt;" and the links won't work

    # justify="center", center the column labels
    csv.to_html(output, index=False, escape=False, formatters=formatter,
                justify="center", na_rep="")


path_input = "/Users/cosmejordan/Desktop/BachelorProject/_Code/Buggy_CSVs/"
path_output = "/Users/cosmejordan/Desktop/BachelorProject/_Code/Buggy_MDs/"
files = []
for r, d, f in os.walk(path_input):
    for file in f:
        files.append(os.path.join(r, file))

for f in files:
    base = os.path.basename(f)
    output_name = path_output + os.path.splitext(base)[0]

    csv_to_html(f,
                output_name + ".md")

    csv_to_html(f,
                output_name + ".html")
