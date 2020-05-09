from jinja2 import Environment, FileSystemLoader,Template
import os

class LibraryPageFiller:
	def __init__(self):
		pass
		



	def run(self,libraryName):
		env = Environment(loader=FileSystemLoader('templates'))
		template = env.get_template('library_template.html')

		template.stream(library_name = libraryName).dump('libraries/'+libraryName+'.html')


