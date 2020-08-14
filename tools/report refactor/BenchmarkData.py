import pandas as pd
from pandas import DataFrame
import numpy as np
import sys
import json

INDEX_NAMES = ["Fuzzer", "Library","Program","Campaign","Metric","BugID"]


#TODO add retrival of experiment infomation (Campaign udration)
class BenchmarkData:

	def __init__(self,filename):

		self.filename = filename
		print("Load json")
		with open(filename) as f:
			json_data =json.load(f)
		
		dictionnary= {(fuzzer,lib,sublib,campaign_num, metric, bug_id) : [time] 
						for fuzzer, innerDict in json_data.items() 
						for lib, innerDict1 in innerDict.items() 
						for sublib, innerDict2 in innerDict1.items() 
						for campaign_num, innerDict3 in innerDict2.items() 
						for metric, innerDict4 in innerDict3.items()
						for bug_id,time in innerDict4.items()}
		df = DataFrame.from_dict(dictionnary)
		df = df.transpose()
		df.columns = ['Time']
		df.index = df.index.set_names(INDEX_NAMES)
		#Sorting for later performance gain
		self.df = df.sort_index()

		#extract campaign duration here from json
	
	def get_frame(self):
		return self.df
