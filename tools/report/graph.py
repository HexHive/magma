import json
import matplotlib.pyplot as plt
import pandas as pd
from pandas.io.json import json_normalize
from pandas import DataFrame
from matplotlib import cm




def transformDataIntoNonUniqueReachedAndTriggeredBugs(data) :
	reached = data.copy()
	triggered = data.copy()
	for col in data :
		reached[col] =reached[col].apply(lambda x : x[0])
		triggered[col] =triggered[col].apply(lambda x : x[1])
	return reached,triggered


def transformDataIntoUniqueReachedAndTriggeredBugs(data) :
	reached = data.copy()
	triggered = data.copy()
	for col in data :
		reached[col] =reached[col].apply(lambda x : set(x[0]))
		triggered[col] =triggered[col].apply(lambda x : set(x[1]))
	return reached,triggered

def boxplot(data,title) :
	fig = plt.figure()
	fig.canvas.set_window_title(title)
	data.boxplot(figsize=(0.34,20))
	plt.title(title)
	


def barplot(data,title) :
	data.transpose().plot.bar()
	plt.title(title)


def barplotReachedVsTriggeredForALibrary(reached,triggered,library,title) :
		#fig = plt.figure()
		#fig.canvas.set_window_title(title)
		df = DataFrame({'Reached' : reached[library],'Triggered' : triggered[library]})
		df.plot.bar()
		plt.title(title)
		

def transformJsonToContainAListOfReachedAndTriggeredBugs(json_string) :
	updated_json = {}
	with open(json_string) as campaign_results :
		data = json.load(campaign_results)
		for fuzzer in data :
			updated_json[fuzzer] = {}
			for librarie in data[fuzzer] :
				updated_json[fuzzer][librarie] = ([],[])
				for sublibraries in data[fuzzer][librarie] :
					for campaign in data[fuzzer][librarie][sublibraries] :
						for conditions in data[fuzzer][librarie][sublibraries][campaign] :
							if conditions == 'reached' :
								for reached_bugs in data[fuzzer][librarie][sublibraries][campaign][conditions]:
									updated_json[fuzzer][librarie][0].append(reached_bugs)
							
							elif conditions == 'triggered' :
								for triggered_bugs in data[fuzzer][librarie][sublibraries][campaign][conditions]:
									updated_json[fuzzer][librarie][1].append(triggered_bugs)
	return updated_json







data = transformJsonToContainAListOfReachedAndTriggeredBugs('20200501_24h.json')
df = pd.DataFrame(data).transpose()
reached_non_unique,triggered_non_unique = transformDataIntoNonUniqueReachedAndTriggeredBugs(df)
reached_unique,triggered_unique = transformDataIntoUniqueReachedAndTriggeredBugs(df)
for col in triggered_non_unique :
	triggered_non_unique[col] = triggered_non_unique[col].apply(lambda x : len(x))
	reached_non_unique[col] = reached_non_unique[col].apply(lambda x : len(x))
	triggered_unique[col] = triggered_unique[col].apply(lambda x : len(x))
	reached_unique[col] = reached_unique[col].apply(lambda x : len(x))


print(reached_unique)
boxplot(reached_unique,"Repartition of unique bugs reached by all fuzzer in a tested libraries")
barplotReachedVsTriggeredForALibrary(reached_unique,triggered_unique,'libpng',"Reached and Triggered unique bug count for each fuzzer in libpng")
plt.show()




