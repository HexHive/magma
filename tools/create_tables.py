import re
import os

# Dependence on pandas
import pandas as pd

# Dependence on beautiful soup
import bs4 as bs


XML_PARSER = "lxml"
PORTED = "Ported"


def html_to_csv(name, output):
    '''
    Convert html file to csv file and replacing html links by real ones. Also,
    convert the ticks to "TRUE" or "FALSE"

    Parameters
    ----------
    name(string):
        The name of the html file (e.g example.html) to convert to csv

    output(string):
        The name of ouptuf file (e.g example.csv)
    '''

    # Open file on mode reading
    f = open(name, "r")
    print(name)

    # Using soup with XML_PARSER
    soup = bs.BeautifulSoup(f, XML_PARSER)

    # Close file
    f.close()

    # Find every <a href="...">...</a> links
    links = soup.find_all("a")

    cleanSoup = str(soup)

    # For each link <a href="...">...</a> replace the href by the link itself
    for link in links:
        cleanSoup = cleanSoup.replace(str(link), link["href"])

    # Replace special elements that were used
    cleanSoup = cleanSoup.replace("✓", "TRUE")
    cleanSoup = cleanSoup.replace("✗", "FALSE")

    # This should only give one table
    for i, df in enumerate(pd.read_html(str(cleanSoup))):
        df.to_csv(output, index=False)


def linkify(entry):
    '''
    Replace all http links by html <a href="...">link</a>

    Parameters
    ----------
    entry(object (pandas)):
        A pandas entry
    '''

    # We only linkify for string, and not null values or booleans
    if(isinstance(entry, str)):

        # We use a "set" to avoid problems with duplicates when we
        # replace each link
        https = set(re.findall(r"http[^\s]+", entry))

        for h in https:
            entry = entry.replace(h, "<a href=\"" + h + "\">link</a>")
    return entry


def csv_to_html(name, output):
    '''
    Convert csv file to html file and replace http links by html links. 
    Also, replace csv "TRUE", "FALSE" to ticks

    Parameters
    ----------
    name(string):
        The name of ouptuf file (e.g example.csv) to convert to html

    output(string):
        The name of the html file (e.g example.html)
    '''

    csv = pd.read_csv(name, sep=',')

    # We change links to html links for each columns and each rows
    for c in csv.columns.values:
        csv[c] = csv[c].apply(linkify)

    # For the ported columns we replace the "TRUE", "FALSE" for tick values
    csv[PORTED] = csv[PORTED].apply(lambda e: "&#10003;" if e
                                    else "&#10007;")

    # Making sure that tick boxes are centered in the table
    # "Ported" column
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
    Parameters
    ----------
    input_path(string):
        Path to input folder

    output_path(string):
        Path to output folder

    function(reference to function (either csv_to_html or html_to_csv)):
        The name of ouptuf file (e.g example.csv) to convert to html

    extension:
        The name of ouptuf file (e.g example.csv) to convert to html
    '''

    files = []
    for r, d, f in os.walk(input_path):
        for file in f:
            files.append(os.path.join(r, file))

    for f in files:
        # For each files we get the file name (e.g. /a/b/c/d.csv gives "d.csv")
        base = os.path.basename(f)

        # We split d.csv to "d" and "csv" and only keep "d"
        output_name = output_path + os.path.splitext(base)[0]

        function(f, output_name + extension)
