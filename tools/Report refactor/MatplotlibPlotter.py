from Plotter import Plotter
from Metric import Metric
from DataProcessing import DataProcessing
import matplotlib
from matplotlib import colors
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import scikit_posthocs as sp
import scipy.stats as ss
import pandas as pd


class MatplotlibPlotter(Plotter,DataProcessing):
	

	def __init__(self):
		self.dp = DataProcessing()
		

	def mean_and_standard_deviation(self,metric):
		data = self.dp.mean_and_standard_deviation_data(metric)
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
		#plt.title("Mean number of bugs triggered by different fuzzers for each target library")
		#plt.savefig("test.svg", format="svg")

	def expected_time_to_trigger(self):
		ett,agg = self.dp. expected_time_to_trigger_data()
		#TODO Order the fuzzers -> add function to data processing
		#fuzzer_order = self.get_fuzzer_from_most_to_less_triggered_bugs(data)
		#df= df[fuzzer_order]
		#Sort the bug by aggragate time
		ett = ett.droplevel(0)
		ett["Aggregate"] = agg.droplevel(0)
		ett.sort_values(by='Aggregate' , inplace=True)
		ett = ett.drop(labels='Aggregate',axis=1)
		
		fuzzers = list(ett.columns)
		bug_id = list(ett.index)
		annotations = ett.copy()
		annotations[fuzzers] = annotations[fuzzers].applymap(lambda x : self.generate_variable_label_units(x))
		fig, ax = plt.subplots(figsize=(10,10))  
		plt.yticks(rotation=0)
		plt.xlabel("Fuzzers")
		plt.ylabel("Bugs") 
		heat_map = sns.heatmap(np.array(ett),cmap='seismic',
		                        xticklabels=fuzzers,
		                        yticklabels=bug_id,
		                        annot=np.array(annotations),
		                        fmt='s',
		                        norm=colors.PowerNorm(gamma=0.32),
		                        ax=ax)
		ticks = [20850,41700,83400,166800]
		tick_labels = ["6h","12h","24h","48h"]
		cbar = ax.collections[0].colorbar
		cbar.set_ticks(ticks)
		cbar.set_ticklabels(tick_labels)
		ax.patch.set(fill='True',color='darkgrey')
		ax.set_title("Exptected time-to-trigger-bug for each fuzzer", fontsize =20)
		ax.xaxis.tick_top()
		
		plt.show(block=False)
		plt.pause(2)
		plt.close()


	def statistical_significance(self,symmetric):
		data = self.dp.statistical_significance_data().reset_index().drop('Campaign',1)
		rename = {"aflplusplus" : "afl++","honggfuzz": "hfuzz"}
		data = data.replace({"Fuzzer": rename})
		
		g_data = data.groupby(['Library'])
		fig, ax = plt.subplots(nrows=1, ncols=7, figsize=(14, 7))
		
		for i, target in enumerate(g_data.groups):
			figx = i // 7
			figy = i % 7
			#axes = ax[figx, figy]
			axes = ax[i]

			if i != 0:
			    axes.get_yaxis().set_visible(False)

			axes.set_title(target)
			p_values = self.two_sided_u_test(g_data.get_group(target))
			self.heatmap_plot(p_values, symmetric=False, axes=axes, labels=False, cbar_ax_bbox=[1, 0.4, 0.02, 0.2])

		fig.tight_layout(pad=2.0)
		# fig.delaxes(ax[1,3])
		fig.savefig('signplot.svg', bbox_inches=matplotlib.transforms.Bbox.from_bounds(0, 0, 15, 7))





	def two_sided_u_test(self,benchmark_snapshot_df):
		"""Returns p-value table for two-tailed Mann-Whitney U test."""
		return self.create_p_value_table(benchmark_snapshot_df,
		                             ss.mannwhitneyu,
		                             alternative='two-sided')


	def create_p_value_table(self,benchmark_snapshot_df,
	                          statistical_test,
	                          alternative="two-sided"):
	    """Given a benchmark snapshot data frame and a statistical test function,
	    returns a p-value table. The |alternative| parameter defines the alternative
	    hypothesis to be tested. Use "two-sided" for two-tailed (default), and
	    "greater" or "less" for one-tailed test.
	    The p-value table is a square matrix where each row and column represents a
	    fuzzer, and each cell contains the resulting p-value of the pairwise
	    statistical test of the fuzzer in the row and column of the cell.
	    """

	    def test_pair(measurements_x, measurements_y):
	        return statistical_test(measurements_x,
	                                measurements_y,
	                                alternative=alternative).pvalue
	  
	    groups = benchmark_snapshot_df.groupby('Fuzzer')
	    samples = groups['Bugs'].apply(list)
	    fuzzers = samples.index

	 
	    data = []
	    for f_i in fuzzers:
	        row = []
	        for f_j in fuzzers:
	            if f_i == f_j:
	                # TODO(lszekeres): With Pandas 1.0.0+, switch to:
	                # p_value = pd.NA
	                p_value = np.nan
	            elif set(samples[f_i]) == set(samples[f_j]):
	                p_value = np.nan
	            else:
	                p_value = test_pair(samples[f_i], samples[f_j])
	            row.append(p_value)
	        data.append(row)

	    p_values = pd.DataFrame(data, index=fuzzers, columns=fuzzers)
	    return p_values

	def heatmap_plot(self,p_values, axes=None, symmetric=False, **kwargs):
	    """Draws heatmap plot for visualizing statistical test results.
	    If |symmetric| is enabled, it masks out the upper triangle of the
	    p-value table (as it is redundant with the lower triangle).
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



	def generate_variable_label_units(self,elem) :
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

	

