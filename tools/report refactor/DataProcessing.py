import pandas as pd
from pandas import DataFrame
from math import sqrt
import numpy as np
from Metric import Metric
from BenchmarkData import BenchmarkData
from math import inf

CAMPAIGN_DURATION = 83400 #to be extracted from json
INDEX_ORDER = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]


class DataProcessing:

	def __init__(self):
		pass

	
	"""
	Reshapes the intial dataframe in a way to obtain the mean and
	variance of the number of bugs that have satisfied the metric
	
	Parameters
	----------
 
  	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]
        
	"""
	@staticmethod
	def average_time_to_metric_data(df,metric) :
		#Select only bugs that satisfy the metric and then calculate the mean time by grouping
		average_time = df.iloc[df.index.get_level_values('Metric') == metric].mean(level=['Fuzzer','Library','Program'])
		return average_time

	
	"""
	Reshapes the data to compute the expected time-to-trigger for every triggered bug.
	It also computes the aggregate time for every bug, which can be used to sort the bugs
	
	Parameters
	----------

	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]
         
	"""
	@staticmethod
	def expected_time_to_trigger_data(df) :
		
		"""
		Helper function to compute the expected time to trigger for every bug

		Parameters
		----------

		N (MultiIndex Dataframe)
  			Levels = ["Fuzzer", "Library","Program","BugID"]
  			Contains the total number of campaigns in every level

  		M (MultiIndex Dataframe)
  			Levels = ["Fuzzer", "Library","Program","BugID"]
  			Contains the total number of campaigns where bug with BugID was triggered

  		t (MultiIndex Dataframe)
  			Levels = ["Fuzzer", "Library","Program","BugID"]
  			Contains the mean time to trigger for every bug with BugID


		"""
		def expected_time_to_bug(N,M,t):
			N_minus_M = N - M
			lambda_t = np.log(N /N_minus_M)
			ett = ((M * t) + N_minus_M * (CAMPAIGN_DURATION / lambda_t)) / N
			return ett


		df_triggered = df.iloc[df.index.get_level_values('Metric') == Metric.TRIGGERED.value]
		t = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).mean()
		M = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).count()
		N = df.reset_index().groupby(['Fuzzer', 'Library','Program'])['Campaign'].nunique().reindex(M.index).to_frame()
		N.columns = ['Time']
		print(N)
		df_ett = expected_time_to_bug(N,M,t).groupby(['Fuzzer','Library','BugID']).min().droplevel(1).unstack().transpose()
	
		#Aggregate time computation
		#NOT COMPLETE
		#Extracting the programm for which the bug did best
		prog_bug = expected_time_to_bug(N,M,t).reset_index().groupby(['Fuzzer','Library','BugID'])['Program','Time'].min()
		prog_bug = prog_bug.groupby(['Fuzzer','Library','Program','BugID']).last()

		#Computing the average timeeto trigger bug over all fuzzers and libraries including all programms
		t_agg = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).sum()
		M_agg = df_triggered.groupby(['Fuzzer','Library','Program','BugID']).count()
		
		#Only considering the program where the bug did best
		t_agg = t_agg[t_agg.index.isin(prog_bug.index)]
		M_agg = M_agg[M_agg.index.isin(prog_bug.index)]
		M_agg = M_agg.groupby('BugID').sum()
		t_agg = t_agg.groupby('BugID').sum()/M_agg
		


		#Counting the number of campaigns for each bug in every program,library and fuzzer
		N_agg = df.reset_index().groupby(['Fuzzer','Library','Program'])['Campaign'].nunique().reindex(prog_bug.index).to_frame()		
		
		
		def expand_list(x) :
			while(len(x) < 10) :
				x.append(x[0])
			return sum(x)
		#Camapigns where the bug was not trigger should still count but couldn't find a way to add them.
		#Therefor if we miss some data I expended the list with the first value
		N_agg = N_agg.groupby(['BugID'])['Campaign'].apply(list).apply(lambda x : expand_list(x)).to_frame()
		N_agg.columns = ['Time']

		agg = expected_time_to_bug(N_agg,M_agg,t_agg)
		agg = agg.sort_values(by=['Time'])
		return df_ett,agg

	

	"""
	Reshapes data to represent the mean and standard deviation time to metric
	For each Fuzzer,Target pair calculate the mean and standard deviation of the time to metric
	
	Parameters
	----------

	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]


    metric (string):
    	choosen metric
         
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
	
	Parameters
	----------

	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]
         
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

	Parameters
	----------

	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]
         
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
	
	Parameters
	----------

	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]
  	
  	fuzzer (string)
  		choosen fuzzer
  	
  	library (string)
  		choosen library/target
  	
  	metric (string)
  		choosen metric

         
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


	"""
	Returns a Dataframe that has a row for every fuzzer and 3 columns (x,y,ci) representing repectively
	the datapoints to place on x and y axis alongside with the error margin
	
	Parameters
	----------

	df (MultiIndex Dataframe)
  		Levels = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]
  	
  	library (string)
  		choosen library/target
  	
  	metric (string)
  		choosen metric

         
	"""	
	@staticmethod
	def line_plot_data(df,library,metric) :


		def get_step_value(fuzzer,x_values, campaigns):
			df_fuzz = campaigns.iloc[campaigns.index.get_level_values('Fuzzer') == fuzzer]
			g = df_fuzz.groupby(['Campaign'])['Time'].apply(lambda x : sorted(list(x)))
			num_campaigns = len(g.index)
			def step_val(series,x):
				serie = series[series.index <= x]
				if (serie.empty):
					return 0
				return serie.iloc[-1] + 1
			y_values = [[step_val(pd.Series([a for a in range(0,len(g.loc[str(campaign)]))],index=g.loc[str(campaign)]),x) for campaign in range(0,num_campaigns)] for x in x_values]
			
			return y_values

		max_x = -1
		max_y = -1
		min_x = inf
		df_metric = df.iloc[df.index.get_level_values('Metric') == metric]
		df_lib = df_metric.iloc[df_metric.index.get_level_values('Library') == library]
		#For each BugID in each campaign in multiple Programs, only retain the smallest time to metric
		df_lib = df_lib.groupby(['Fuzzer','Library','Campaign','BugID']).min()
		
		x_plot = df_lib.groupby(['Fuzzer'])['Time'].apply(lambda x : sorted(set(x))).to_frame()
		x_plot.columns = ['x']
		y_plot = x_plot
		index = x_plot.index
		y_plot = y_plot.reset_index()
		y_plot = y_plot.apply(lambda f : get_step_value(f['Fuzzer'],f['x'],df_lib),axis=1).to_frame()
		y_plot.index = index
		y_plot.columns = ['y']
		df_aggplot = x_plot
		df_aggplot['y'] = y_plot
		df_aggplot['ci'] = df_aggplot['y'].apply(lambda x : [1.96 * np.nanstd(i) / np.nanmean(i) for i in x])
		df_aggplot['y'] = df_aggplot['y'].apply(lambda x : [np.nanmean(i) for i in x])
		
		#First weget the max values per entry of the x list.
		#The list is already sorted therefor we take the last element
		x_max = max([max(x) for x in df_aggplot['x']])
		x_min = min([min(x) for x in df_aggplot['x']])
		y_max = max([max(y) for y in df_aggplot['y']])
		return df_aggplot, x_max, y_max, x_min


		


	
		
	

	

	






