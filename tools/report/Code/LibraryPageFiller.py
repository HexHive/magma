from jinja2 import Environment, FileSystemLoader, Template
import os
from Render import Render


class LibraryPageFiller(Render):
        def __init__(self):
                pass

        def run(self, libraryName):
                env = Environment(loader=FileSystemLoader('templates'))
                template = env.get_template('library_template.html')

                template.stream(library_name=libraryName).dump('libraries/'+libraryName+'.html')

        def render(self, file_name, output_file_name, description):
                # TODO
                print("TODO...")
                print("You forgot to implement that...")
                pass
