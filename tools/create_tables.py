import pandas as pd
import bs4 as bs
import re
import os

XML_PARSER = "lxml"
PORTED = "Ported"


def html_to_csv(name, output):
    links = []
    f = open(name, "r")
    print(name)
    soup = bs.BeautifulSoup(f, XML_PARSER)
    print(soup)
    f.close()
    links = soup.find_all("a")
    cleanSoup = str(soup)

    for link in links:
        cleanSoup = cleanSoup.replace(str(link), link["href"])

    cleanSoup = cleanSoup.replace("✓", "TRUE")
    cleanSoup = cleanSoup.replace("✗", "FALSE")

    # This should only give one table
    for i, df in enumerate(pd.read_html(str(cleanSoup))):
        df.to_csv(output, index=False)


def linkify(entry):
    if(isinstance(entry, str)):

        # We use a "set" to avoid problems with duplicates when we
        # replace each link
        https = set(re.findall(r"http[^\s]+", entry))
        for h in https:
            print(h)
            print("<a href=\"" + h + "\">link</a>")
            entry = entry.replace(h, "<a href=\"" + h + "\">link</a>")
    return entry


def csv_to_html(name, output):
    csv = pd.read_csv(name, sep=',')
    for c in csv.columns.values:
        csv[c] = csv[c].apply(linkify)

    csv[PORTED] = csv[PORTED].apply(lambda e: "&#10003;" if e
                                    else "&#10007;")

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
                justify="center", na_rep="", border=0, render_links=True)


def create_files_from_folder(input_path, output_path, function, extension):
    '''
    ex = "extension"
    '''

    files = []
    for r, d, f in os.walk(input_path):
        for file in f:
            files.append(os.path.join(r, file))

    for f in files:
        base = os.path.basename(f)
        output_name = output_path + os.path.splitext(base)[0]

        function(f, output_name + extension)


# Example code
# input_path = ""
# output_path = ""
# HTML = ".html"
# MD = ".md"
# create_files_from_folder(input_path, output_path, csv_to_html, HTML)
# create_files_from_folder(input_path, output_path, csv_to_html, MD)
