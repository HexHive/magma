import pandas as pd
from pandas import DataFrame
from math import sqrt
import numpy as np
from Metric import Metric
from DataLoader import DataLoader

CAMPAIGN_DURATION = 83400
INDEX_NAMES = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]


class DataProcessing:

	def __init__(self):
		self.df = DataLoader().get_frame()
		#extract campaign duration here from json

	

	"""
	Reshapes data to represent the average time to metric
	"""
	def average_time_to_metric_data(self,metric) :
		average_time = self.df.iloc[self.df.index.get_level_values('Metric') == metric].mean(level=['Fuzzer','Library','Program'])
		return average_time

	
	"""
	
	"""
	def expected_time_to_trigger_data(self) :
		
		df_triggered = self.df.iloc[self.df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
		#Average trigger time of bug
		t = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).mean()
		#Number of campaigns where a given bug was triggered
		M = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).count()
		#Total number of campaigns
		N = self.df.reset_index().groupby(['Fuzzer', 'Library','Program'])['Campaign'].nunique().reindex(M.index).to_frame()
		N.columns = ['Time']
		df_ett = self.expected_time_to_bug(N,M,t).groupby(['Fuzzer','Library','BugID']).min().droplevel(1).unstack().transpose()
		
		t_agg= df_triggered.groupby(['Library','BugID']).mean()
		M_agg = df_triggered.groupby(['Library','BugID']).count()
		N_agg = self.df.reset_index().groupby(['Fuzzer', 'Library','Program'])['Campaign'].nunique().reindex(M.index).to_frame()
		N_agg.columns = ['Time']
		N_agg = N_agg.groupby(['BugID']).sum()
		agg = self.expected_time_to_bug(N_agg,M_agg,t_agg)
		agg = agg.sort_values(by=['Time'])
		
		return df_ett,agg

	"""
	Reshapes data to represent the mean and standard deviation time to metric
	"""
	def mean_and_standard_deviation_data(self,metric):

		df = self.df.reset_index().groupby(["Fuzzer", "Library","Program","Campaign","Metric"])['BugID'].nunique().to_frame()
		std_bugs = df.iloc[df.index.get_level_values('Metric') == metric].std(level=["Fuzzer", "Library"])
		std_bugs.columns = ['std']
		mean_bugs = df.iloc[df.index.get_level_values('Metric') == metric].mean(level=['Fuzzer','Library'])
		mean_bugs.columns = ['mean']
		return mean_bugs.join(std_bugs)

	"""
	Helper function to compute ETT
	"""
	def expected_time_to_bug(self,N,M,t):
		N_minus_M = N - M
		lambda_t = np.log(N /N_minus_M)
		ett = ((M * t) + N_minus_M * (CAMPAIGN_DURATION / lambda_t)) / N
		return ett




	def statistical_significance_data(self):
		df_triggered = self.df.iloc[self.df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
		#Extract the number of unique bugs per campaign
		df = df_triggered.reset_index().groupby(['Fuzzer','Library','Campaign'])['BugID'].nunique()
		#Unstack and stack back to fill the missing campaign values
		df= df.unstack('Campaign', fill_value=0).stack(level=0).to_frame()
		df.columns = ['Bugs']
		return df
		
		

	

	






