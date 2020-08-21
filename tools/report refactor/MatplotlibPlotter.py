from Plotter import Plotter
from Metric import Metric
from BenchmarkData import BenchmarkData
from DataProcessing import DataProcessing
import matplotlib
from matplotlib import colors
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import scikit_posthocs as sp
import scipy.stats as ss
import pandas as pd

TIMESTAMPS = {20850 :"6h",41700 : "12h",83400 : "24h",166800 : "48h"}

class MatplotlibPlotter(Plotter):
	

	def __init__(self,bd):
		self.df = bd.get_frame()
		

	"""
	Represents in a barplot the mean and variance of te number of bugs that
	have satisfied the metric
	
	Parameters
	----------
 
    metric (string):
    	choosen metric
        
	"""
	def mean_and_standard_deviation(self,metric):
		data = DataProcessing.mean_and_standard_deviation_data(metric,self.df)
		means = data['mean'].unstack().transpose()
		std = data['std'].unstack().transpose()
		fig, ax = plt.subplots()
		means.plot.bar(yerr=std,
						ax=ax,figsize=(20,10),
						fontsize=14)
		plt.ylabel('Number of Bugs Triggered',fontsize=14)
		plt.xlabel('Targets',fontsize=14)
		plt.legend(loc=1, prop={'size': 17})
		fig.savefig('output/data/mean_variance_bar.svg')
		plt.close()

	"""
	Represents the "hardness" of each triggered bug in a heatmap
	by computing the expected time to trigger for each bug
	"""
	def expected_time_to_trigger(self):
		ett,agg = DataProcessing.expected_time_to_trigger_data(self.df)
	
		#Compute the order of the fuzzer that found the most bugs in descending order
		fuzzer_order = DataProcessing.number_of_unique_bugs_found_data(self.df)
		fuzzer_order = fuzzer_order.sort_values(by=['Bugs'],ascending = False).reset_index()['Fuzzer'].tolist()
		
		#Sort the bug by aggragate time
		ett = ett.droplevel(0)
		ett["Aggregate"] = agg
		ett.sort_values(by='Aggregate', inplace=True)
		ett = ett.drop(labels='Aggregate', axis=1)
		#Reordering the fuzzers
		ett = ett[fuzzer_order]
		fuzzer_label = list(ett.columns)
		bug_label  = list(ett.index)
		annotations = ett.copy()
		annotations[fuzzer_label] = annotations[fuzzer_label].applymap(lambda x : self.time_labels(x))
		fig, ax = plt.subplots(figsize=(10,10))  
		plt.yticks(rotation=0)
		#Norm foactor has to been precomputed
		heat_map = sns.heatmap(np.array(ett),cmap='seismic',
		                        xticklabels=fuzzer_label,
		                        yticklabels=bug_label,
		                        annot=np.array(annotations),
		                        fmt='s',
		                        norm=colors.PowerNorm(gamma=0.32),
		                        ax=ax)
		#Color bar properties
		cbar = ax.collections[0].colorbar
		cbar.set_ticks([x for x in TIMESTAMPS.keys()])
		cbar.set_ticklabels([x for x in TIMESTAMPS.values()])
		ax.patch.set(fill='True',color='darkgrey')
		ax.set_title("Exptected time-to-trigger-bug for each fuzzer", fontsize =20)
		ax.xaxis.tick_top()
		fig.savefig('output/data/expected_time_to_bug_heat.svg')
		plt.close()
		
	"""
	Creates a 2D array plot representing the statistical significance
	between every pair of fuzzers on a target libary
	
	Parameters
	----------
    libraries (list):
       The targets to plot the statistical significance from

    symmetric (boolean):
    	masks the upper-triangle of the table
        
	"""
	def statistical_significance(self,libraries,symmetric):

		
		data = DataProcessing.statistical_significance_data(self.df)
		rename = {"aflplusplus" : "afl++","honggfuzz": "hfuzz"}
		data = data.replace({"Fuzzer": rename})

		#If there is no library as argument we compute the plot for every fuzzer
		if not libraries :
			libraries = list(set(data.index.get_level_values('Library').tolist()))

		fig, ax = plt.subplots(nrows=1, ncols=len(libraries), figsize=(12, 7))
		for library in libraries :
			#Retrieve only the data concerning the target library
			i = libraries.index(library)
			figx = i
			#Currently the plot only expand in a row
			if len(libraries) == 1 :
				axes = ax
			else :
				axes = ax[figx]

			if i != 0:
				axes.get_yaxis().set_visible(False)
			lib_data = data.xs(library, level='Library',drop_level=True)
			axes.set_title(library)


			#Computing p_values of the library
			p_values = self.compute_p_values(lib_data)
			self.heatmap_plot(p_values, symmetric=symmetric, axes=axes, labels=False, cbar_ax_bbox=[1, 0.4, 0.02, 0.2])
		fig.tight_layout(pad=2.0)
		fig.savefig('output/data/signplot.svg', bbox_inches=matplotlib.transforms.Bbox.from_bounds(0, 0, 13, 10))
		plt.close()


	"""
	Create box plot graph showing the time distribution
	of bugs who satisfid the metric

	Parameters
	----------
	fuzzer (string):
        From which fuzzer

    library (string):
        From which library

    metric (string):
      	choosen metric

	"""
	def bug_metric_boxplot(self, fuzzer, library, metric):

		df = DataProcessing.bug_list(self.df,fuzzer,library,metric)
		
		#We increase the width so smaller boxes can be seen
		boxprops = dict(linestyle='-', linewidth=2, color='k')
		df.transpose().boxplot(figsize=(12, 10), boxprops=boxprops, vert=False)
		plt.title(metric + ". Fuzzer: " + fuzzer + ". Library:" + library)
		plt.ylabel("Bug Number")
		plt.xlabel("Time (seconds)")
		plt.ylim(bottom=0)
		plt.savefig("data/" + fuzzer + "_" + library + "_" + metric + "_box.svg", format="svg", bbox_inches="tight")
		plt.close()

	"""
	Creates a line plot for each fuzzer,target pair
	If fuzzers is empty then a plot for every known fuzzer will be computed
	
	Parameters
	----------
	fuzzers (list) : 
		list of fuzzer names
	library (Ssring) :
		target used to compute the line plots
	metric (string)
		choosen metric

	"""
	def line_plot_unqiue_bugs(self,fuzzers,library,metric) :
		df, x_max, y_max, x_min = DataProcessing.line_plot_data(self.df,library,metric)
		#If there is no fuzzer as argument we compute the plot for every fuzzer
		if not fuzzers :
			fuzzers = df.index.values.tolist()
		fig, ax = plt.subplots(nrows=1,ncols=len(fuzzers), figsize=(10, 5))
		
		for fuzzer in fuzzers:
			i = fuzzers.index(fuzzer)
			figx = i
			#Currently the plot only expand in a row
			if(len(fuzzers) == 1) :
				axes = ax
			else :
				axes = ax[figx]

			x = np.array(df['x'][fuzzer])
			y = np.array(df['y'][fuzzer])
			ci = np.array(df['ci'][fuzzer])

			# axes.set_xscale('log')
			axes.step(x, y)
			axes.fill_between(x, (y - ci), (y + ci), color='b', alpha=.1)

			axes.set_title(fuzzer)
			axes.set_ylim((0, y_max + 5))
			axes.set_xlim((x_min, x_max + 5))
		plt.tight_layout(pad=2.0)
		fig.savefig('output/data/lineplot.svg', bbox_inches=matplotlib.transforms.Bbox.from_bounds(0, 0, 13, 10))
		plt.close()



#Helper functions

	"""
	Computes the p_values used in the statistical significance plot
	for a specific target

	
	Parameters
	----------
	benchmark_library_data_df (Dataframe) : 
		Data of a target
		

	"""
	def compute_p_values(self,benchmark_library_data_df):
		#For every fuzzer we gather in a list the number of times a bug was found
		#Entry 0 in the list is for cmapaign 0
		fuzzer_data = benchmark_library_data_df.groupby('Fuzzer')['Bugs'].apply(list)	
		fuzzer_label = fuzzer_data.index.tolist()
		#Constructing the index from the cross product of the fuzzer_label
		#The index has already the shape of the targeted p_value dataframe
		index = pd.MultiIndex.from_product([fuzzer_label,fuzzer_label],names=['Outter','Inner'])
		#Creation of the p_value Dataframe with the previously computed index.
		#Index has to been reset such that the multi index values can be passed as argument to the lambda function
		p_values = pd.DataFrame(index=index,columns=['p_value']).fillna(np.nan).reset_index()
		p_values = p_values.apply(lambda f : self.two_sided_test(f['Outter'],f['Inner'],fuzzer_data),axis=1)
		#Index has to been reassigned as it has been reset previously
		p_values.index = index
		#Unstacking the Dataframe gives it the expected 2 dimensional shape for a p_value array
		return p_values.unstack()

	#Helper function to compute the p_value between two fuzzer_label
	def two_sided_test(self,f1,f2,fuzzer_data) :
		if f1 == f2 or set(fuzzer_data[f1]) == set(fuzzer_data[f2]) :
			return
		else :
			return ss.mannwhitneyu(fuzzer_data[f1],fuzzer_data[f2], alternative='two-sided').pvalue


	def heatmap_plot(self,p_values, axes=None, symmetric=False, **kwargs):
	    """
	   	Heatmap for p_values
	    """
	    if symmetric:
	        mask = np.zeros_like(p_values)
	        mask[np.triu_indices_from(p_values)] = True
	    heatmap_args = {
	        'linewidths': 0.5,
	        'linecolor': '0.5',
	        'clip_on': False,
	        'square': True,
	        'cbar_ax_bbox': [0.85, 0.35, 0.04, 0.3],
	        'mask': mask if symmetric else None,
	    }
	    heatmap_args.update(kwargs)
	    return sp.sign_plot(p_values, ax=axes, **heatmap_args)


	"""
	Label function to make the expected time to trigger heatmap
	more understandable
	"""
	def time_labels(self,elem) :
		if self.is_nan(elem) :
		    return elem
		elif elem < 60 :
		    return str(int(elem)) + " sec"
		elif elem < 3600 :
		    return str(int(elem/60)) + " min"
		else : 
		    return str(int(elem/3600)) + " h"


	def is_nan(self,x) :
		return (x != x)




	
		

	

