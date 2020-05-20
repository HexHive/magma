from libraryTemplateGenerate import LibraryTemplate
from Path import Path
from mainPageTemplateGenerate import MainPageTemplate
from plotGenerator import Plots
import os
import sys
import json


def main():

    TEMPLATES = "templates"
    OUTPUTS = "outputs"
    PLOTS = "plots"
    TABLES = "tables"
    LIBRARIES = "libraries"

    current_path = os.path.dirname(__file__)
    # Set paths for templates, output and images
    output_dir = os.path.join(current_path, OUTPUTS)
    libraries_dir = os.path.join(output_dir, LIBRARIES)
    template_dir = os.path.join(current_path, TEMPLATES)
    ##These path should be set according to where the html file will be saved
    plot_dir = os.path.join(output_dir, PLOTS)
    tables_dir = os.path.join(output_dir, TABLES)

    json_data = get_data()  # TODO Use in Plots

    plots = Plots(json_data,Path(template_dir,libraries_dir,tables_dir,plot_dir))
    plots.generate()
    libraries , fuzzers = plots.get_all_targets_and_fuzzers()

    library_template = LibraryTemplate(Path(template_dir, libraries_dir, tables_dir, "../"+PLOTS))
    main_template = MainPageTemplate(Path(template_dir, output_dir, tables_dir, "./"+PLOTS), fuzzers, libraries)


    for library in libraries :
        library_template.render("library_template.html", library+".html")
    main_template.render("report_template.html", "report.html")


def get_data():
    if(len(sys.argv) == 1):
        raise Exception("The program need a json as the first argument")

    with open(sys.argv[1]) as f:
        return json.load(f)


main()
