import sys
import json
import jinja2
from Metric import Metric
from MatplotlibPlotter import MatplotlibPlotter
from BenchmarkData import BenchmarkData
from DataProcessing import DataProcessing

TEMPLATE_DIR = "templates"
OUTPUT_DIR = "output"
def main():

	if(len(sys.argv) == 1):
				raise Exception("The program need a json as the first argument")
	bd = BenchmarkData(sys.argv[1])
	plotter = MatplotlibPlotter(bd)
	plotter.expected_time_to_trigger()
	plotter.line_plot_unqiue_bugs(['afl','aflplusplus','fairfuzz'],'libpng',Metric.TRIGGERED.value)
	plotter.statistical_significance([],False)
	plotter.mean_and_standard_deviation(Metric.TRIGGERED.value)

	jinajEnv = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR))
	template = jinajEnv.get_template("report_template.md")
	#Jinja2 is used to fill html templates witht the plots and data from the report
	rendering = template.render(report_title="Magma benchmark report", fuzzer_list= bd.get_all_fuzzers(), plots_dir="data")
	with open("output/report.html","w") as f:
		f.write(rendering)

	

main()