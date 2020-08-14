from Metric import Metric 
from abc import ABC, abstractmethod

"""
Abstract class representing the behaviour of 
"""
class Plotter:
	
	def __init__(self):
		super().__init__()
		pass


	@abstractmethod
	def mean_and_standard_deviation(self,metric):
		pass

	@abstractmethod
	def expected_time_to_trigger(self):
		pass

	@abstractmethod
	def statistical_significance(self,library,symmetric=False):
		pass

	@abstractmethod
	def bug_metric_boxplot(self, fuzzer, library, metric):
		pass
