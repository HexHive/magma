from jinja2 import Environment, FileSystemLoader,Template
from LibraryPageFiller import LibraryPageFiller
import os



class MainPageFiller :
	
	def __init__(self):
		pass


	def run(self):
		libraryTemp = LibraryPageFiller()
		TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../targets"))
		FUZZER_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../fuzzers"))
		#get the template that has to be loaded
		env = Environment(loader=FileSystemLoader('templates'))
		template = env.get_template('report_template.html')
		fuzzer_list = [ f.name for f in os.scandir(FUZZER_DIR) if f.is_dir() ]
		target_list = [ f.name for f in os.scandir(TARGET_DIR) if f.is_dir() ]
		target_number_of_bug_list = []
		for target in target_list:
			patch_path = os.path.join(TARGET_DIR,target,"patches/bugs")
			libraryTemp.run(target)
			number_of_bugs = len([name for name in os.listdir(patch_path)])
			target_number_of_bug_list.append(number_of_bugs)
		total_bugs = sum(target_number_of_bug_list)
		target_list = zip(target_list,target_number_of_bug_list)
		template.stream(target_list=target_list,total_bugs=total_bugs,fuzzer_list=fuzzer_list).dump('report.html')




