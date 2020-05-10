from jinja2 import Environment, FileSystemLoader, Template
import os

from Code.Render import Render


class MainPageTemplate(Render):
    '''
       A class to represent a the main report page
    '''
    def __init__(self, path):
        '''
        Parameters
        ----------
        path(Path):
            of class Path, used to have all the useful paths

        _file_:
            The file to get the directory from
        '''
        self.path = path
        # Set paths for templates, output and images
        self.template_dir = path.template_dir
        self.output_dir = path.output_dir
        self.tables_dir = path.tables_dir
        self.plot_dir = path.plot_dir

    def render(self, file_name, output_file_name, description):
        '''
        Generate (write to html file) and render reports (html, bugs reports,
        tables,...)

        Parameters
        ----------
        file_name (string):
            The file to get the directory from

        output_file_name (string):
            The name of the html file to write to. (example: "afl")

        description (FuzzerDescription):
            The corresponding description
        '''

        # TODO fix the inheritance for description whcih in libraryGenerate and MainPageGenerate makes no sense

        template = self.path.get_template(file_name)

        '''
        target_list (list of string) ;
            The target libraries name
        
        total_bugs (int) :
            total number of implemented bugs
            
        fuzzer_list (list of string) :
            The benchmarked fuzzers
        '''
        target_list = []
        total_bugs = 0
        fuzzer_list = []
        # TODO Get all the above information from the json passed as argument
        rendering = template.render(target_list=target_list, total_bugs=total_bugs, fuzzer_list=fuzzer_list)

        self.path.write(output_file_name, rendering)

    '''
        def get_parameters(self):
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

    '''
