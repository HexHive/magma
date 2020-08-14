import pandas as pd
from pandas import DataFrame
from math import sqrt
import numpy as np
from Metric import Metric
from BenchmarkData import BenchmarkData

CAMPAIGN_DURATION = 83400
INDEX_NAMES = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]


class DataProcessing:

	def __init__(self):
		pass

	
	"""
	Reshapes data to represent the average time to metric
	"""
	@staticmethod
	def average_time_to_metric_data(df,metric) :
		#Select only bugs that satisfy the metric and then calculate the mean time by grouping
		average_time = df.iloc[df.index.get_level_values('Metric') == metric].mean(level=['Fuzzer','Library','Program'])
		return average_time

	
	"""
	Returns the expected time to trigger for each bug found at least once by a fuzzer
	"""
	@staticmethod
	def expected_time_to_trigger_data(df) :
		
		def expected_time_to_bug(N,M,t):
			N_minus_M = N - M
			lambda_t = np.log(N /N_minus_M)
			ett = ((M * t) + N_minus_M * (CAMPAIGN_DURATION / lambda_t)) / N
			return ett


		df_triggered = df.iloc[df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
		#Average trigger time of bug
		t = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).mean()
		#Number of campaigns where a given bug was triggered
		M = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).count()
		#Total number of campaigns
		N = df.reset_index().groupby(['Fuzzer', 'Library','Program'])['Campaign'].nunique().reindex(M.index).to_frame()
		N.columns = ['Time']
		df_ett = expected_time_to_bug(N,M,t).groupby(['Fuzzer','Library','BugID']).min().droplevel(1).unstack().transpose()
		
		#Need to clarify the way the aggreagate time is computed (because of Programs)
		t_agg= df_triggered.groupby(['Library','BugID']).mean()
		M_agg = df_triggered.groupby(['Library','BugID']).count()
		N_agg = df.reset_index().groupby(['Fuzzer', 'Library','Program'])['Campaign'].nunique().reindex(M.index).to_frame()
		N_agg.columns = ['Time']
		N_agg = N_agg.groupby(['Library']).sum()
		agg = expected_time_to_bug(N_agg,M_agg,t_agg)
		agg = agg.sort_values(by=['Time'])
		
		return df_ett,agg


	"""
	Reshapes data to represent the mean and standard deviation time to metric
	For each Fuzzer,Target pair calculate the mean and standard deviation of the time to metric
	"""
	@staticmethod
	def mean_and_standard_deviation_data(metric,df):
		#For each campaign get the number of unique triggered and reached bugs.
		num_bugs = df.reset_index().groupby(["Fuzzer", "Library","Program","Campaign","Metric"])['BugID'].nunique().to_frame()
		#Group the number of bugs for each pair of Fuzzer and Target and compute std and mean
		std_bugs = num_bugs.iloc[num_bugs.index.get_level_values('Metric') == metric].std(level=["Fuzzer", "Library"])
		std_bugs.columns = ['std']
		mean_bugs = num_bugs.iloc[num_bugs.index.get_level_values('Metric') == metric].mean(level=['Fuzzer','Library'])
		mean_bugs.columns = ['mean']
		#Both dataframes have the same shape, thus we can merge them
		return mean_bugs.join(std_bugs)


	"""
	Returns for each Campaign the number of unique bugs triggered
	"""
	@staticmethod
	def statistical_significance_data(df):
		df_triggered = df.iloc[df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
		#Extract the number of unique bugs per campaign
		df = df_triggered.reset_index().groupby(['Fuzzer','Library','Campaign'])['BugID'].nunique()
		#Unstack and stack back to fill the missing campaign values in case there is ot the same
		#number of campaigns for every target/fuzzer
		df= df.unstack('Campaign', fill_value=0).stack(level=0).to_frame()
		df.columns = ['Bugs']
		return df


	"""
	Computed the total number of found bugs by each fuzzer
	"""
	@staticmethod
	def number_of_unique_bugs_found_data(df):
		#Extracting all found bugs
		df_triggered = df.iloc[df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
		#Reseting the index is necessary to get the number of unique bugs triggered by each fuzzer
		num_trigg = df_triggered.reset_index().groupby(['Fuzzer'])['BugID'].nunique().to_frame()
		num_trigg.columns = ['Bugs']
		return num_trigg


	"""
	Returns the list of bugs along side with the metric time
	A dataframe indexed by the different bugs with columns containing the time for one campaign
	A time can be Nan
	"""
	@staticmethod
	def bug_list(df,fuzzer,library,metric):
		#Extracting the bug fullfilling the metric by putting there metric times into a list
		df_bugs = df.iloc[df.index.get_level_values('Metric') == metric]
		df_bugs = df_bugs.loc[fuzzer,library].groupby('BugID')['Time'].apply(list)
		#Preparing the new index to be the bugs
		index = df_bugs.index.tolist()
		#Reseting the index and converting the data in the column Time into a new Dataframe
		d = pd.DataFrame(df_bugs.reset_index()['Time'].to_list(),index = index)
		return d
	
		
	

	

	






