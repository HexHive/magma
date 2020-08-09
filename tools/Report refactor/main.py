import sys
import json
from Metric import Metric
from MatplotlibPlotter import MatplotlibPlotter


def main():


	plotter = MatplotlibPlotter()
	#mean_var = plotter.mean_and_standard_deviation(metric ='triggered')
	ett = plotter.statistical_significance(symmetric=True)


	

main()