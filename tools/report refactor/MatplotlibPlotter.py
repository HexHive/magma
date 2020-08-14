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
		

	def mean_and_standard_deviation(self,metric):
		data = DataProcessing.mean_and_standard_deviation_data(metric,self.df)
		means = data['mean'].unstack().transpose()
		std = data['std'].unstack().transpose()
		fig, ax = plt.subplots()
		means.plot.bar(yerr=std,
						ax=ax,figsize=(25,10),
						fontsize=14)
		plt.ylabel('Number of Bugs Triggered',fontsize=14)
		plt.xlabel('Targets',fontsize=14)
		plt.legend(loc=1, prop={'size': 17})

		plt.show(block=False)
		plt.pause(2)
		plt.close()


	def expected_time_to_trigger(self):
		ett,agg = DataProcessing.expected_time_to_trigger_data(self.df)
	

		fuzzer_order = DataProcessing.number_of_unique_bugs_found_data(self.df)
		fuzzer_order = fuzzer_order.sort_values(by=['Bugs'],ascending = False).reset_index()['Fuzzer'].tolist()
		
		#Sort the bug by aggragate time
		ett = ett.droplevel(0)
		ett["Aggregate"] = agg.droplevel(0)
		ett.sort_values(by='Aggregate' , inplace=True)
		ett = ett.drop(labels='Aggregate',axis=1)
		ett = ett[fuzzer_order]
		fuzzers = list(ett.columns)
		bug_id = list(ett.index)
		annotations = ett.copy()
		annotations[fuzzers] = annotations[fuzzers].applymap(lambda x : self.time_labels(x))
		fig, ax = plt.subplots(figsize=(10,10))  
		plt.yticks(rotation=0)
		plt.xlabel("Fuzzers")
		plt.ylabel("Bugs") 
		#Norm foactor has to been precomputed
		heat_map = sns.heatmap(np.array(ett),cmap='seismic',
		                        xticklabels=fuzzers,
		                        yticklabels=bug_id,
		                        annot=np.array(annotations),
		                        fmt='s',
		                        norm=colors.PowerNorm(gamma=0.32),
		                        ax=ax)

		cbar = ax.collections[0].colorbar
		cbar.set_ticks([x for x in TIMESTAMPS.keys()])
		cbar.set_ticklabels([x for x in TIMESTAMPS.values()])
		ax.patch.set(fill='True',color='darkgrey')
		ax.set_title("Exptected time-to-trigger-bug for each fuzzer", fontsize =20)
		ax.xaxis.tick_top()
		plt.show()
		

	def statistical_significance(self,library,symmetric):
		data = DataProcessing.statistical_significance_data(self.df)
		rename = {"aflplusplus" : "afl++","honggfuzz": "hfuzz"}
		data = data.replace({"Fuzzer": rename})
		#retrieve onky the data from the target library
		lib_data = data.xs(library, level='Library',drop_level=True)
		fig, ax = plt.subplots(figsize=(10, 10))
		ax.set_title(library)

		#computing p_values of the library
		p_values = self.compute_p_values(lib_data)
		self.heatmap_plot(p_values, symmetric=symmetric, axes=ax, labels=False, cbar_ax_bbox=[1, 0.4, 0.02, 0.2])

		fig.savefig('signplot.svg', bbox_inches=matplotlib.transforms.Bbox.from_bounds(0, 0, 13, 10))
		plt.close()


	def bug_metric_boxplot(self, fuzzer, library, metric):

		df = DataProcessing.bug_list(self.df,fuzzer,library,metric)
		
		
		# We increase the width so smaller boxes can be seen
		boxprops = dict(linestyle='-', linewidth=2, color='k')
		df.transpose().boxplot(figsize=(12, 10), boxprops=boxprops, vert=False)
		plt.title(metric + ". Fuzzer: " + fuzzer + ". Library:" + library)
		plt.ylabel("Bug Number")
		plt.xlabel("Time (seconds)")
		plt.ylim(bottom=0)
		plt.savefig(fuzzer + "_" + library + "_" + metric + "_box.svg", format="svg", bbox_inches="tight")
		plt.close()



#Helper functions



	def compute_p_values(self,benchmark_library_data_df):
		#For every fuzzer we gather in a list the number of times a bug was found
		#Entry 0 in the list is for cmapaign 0
		fuzzer_data = benchmark_library_data_df.groupby('Fuzzer')['Bugs'].apply(list)	
		fuzzers = fuzzer_data.index.tolist()
		#Constructing the index from the cross product of the fuzzers
		#The index has already the shape of the targeted p_value dataframe
		index = pd.MultiIndex.from_product([fuzzers,fuzzers],names=['Outter','Inner'])
		#Creation of the p_value Dataframe with the previously computed index.
		#Index has to been reset such that the multi index values can be passed as argument to the lambda function
		p_values = pd.DataFrame(index=index,columns=['p_value']).fillna(np.nan).reset_index()
		p_values = p_values.apply(lambda f : self.two_sided_test(f['Outter'],f['Inner'],fuzzer_data),axis=1)
		#Index has to been reassigned as it has been reset previously
		p_values.index = index
		#Unstacking the Dataframe gives it the expected 2 dimensional shape for a p_value array
		return p_values.unstack()

	#Helper function to compute the p_value between two fuzzers
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




	
		

	

