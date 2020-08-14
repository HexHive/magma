import sys
import json
from Metric import Metric
from MatplotlibPlotter import MatplotlibPlotter
from BenchmarkData import BenchmarkData
from DataProcessing import DataProcessing


def main():

	if(len(sys.argv) == 1):
				raise Exception("The program need a json as the first argument")
	
	bd = BenchmarkData(sys.argv[1])
	plotter = MatplotlibPlotter(bd)
	mean_var = plotter.mean_and_standard_deviation(metric ='triggered')
	ett = plotter.statistical_significance('libpng',False)


	

main()