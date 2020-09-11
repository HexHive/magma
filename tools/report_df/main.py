import sys
import json
import jinja2
from Metric import Metric
import MatplotlibPlotter
from BenchmarkData import BenchmarkData
import DataProcessing

TEMPLATE_DIR = "templates"
OUTPUT_DIR = "output"

def main():
    if(len(sys.argv) == 1):
        raise Exception("The program needs a json as the first argument")
    bd = BenchmarkData(sys.argv[1])
    MatplotlibPlotter.bug_survival_plots(bd)
    MatplotlibPlotter.expected_time_to_trigger(bd)
    MatplotlibPlotter.unique_bugs_per_library(bd, Metric.TRIGGERED.value)

    ### UNTESTED CODE ###
    # jinjaEnv = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR))
    # template = jinjaEnv.get_template("report_template.md")
    # #Jinja2 is used to fill html templates with the plots and data from the report
    # rendering = template.render(report_title="Magma benchmark report", fuzzer_list= bd.get_all_fuzzers(), plots_dir="data")

    # with open("output/report.html","w") as f:
    #     f.write(rendering)
    #####################

if __name__ == '__main__':
    main()