import os
from Render import Render


class MainPageTemplate(Render):
    '''
       A class to represent a the main report page
    '''

    def __init__(self, path, fuzzers, libraries):
        '''
d        Parameters
        ----------
        path(Path):
            of class Path, used to have all the useful paths

        fuzzers:

        libraries:
        '''
        self.fuzzers = fuzzers
        self.libraries = libraries
        print(libraries)
        super(MainPageTemplate, self).__init__(path)
        # Set paths for templates, output and images
        self.plot_dir = path.plot_dir

    def render(self, file_name, output_file_name):
        """
        Generate (write to html file) and render reports (html, bugs reports,
        tables,...)

        Parameters
        ----------
        file_name (string):
            The file to get the directory from
        output_file_name (string):
            The name of the html file to write to. (example: "afl")
        """

        template = self.path.get_template(file_name)
        TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../targets"))
        FUZZER_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../fuzzers"))
        fuzzer_list = [f.name for f in os.scandir(FUZZER_DIR) if f.is_dir()]
        target_list = [f.name for f in os.scandir(TARGET_DIR) if f.is_dir()]
        print(target_list)
        target_number_of_bug_list = []

        for target in target_list:
            patch_path = os.path.join(TARGET_DIR, target, "patches/bugs")
            number_of_bugs = len([name for name in os.listdir(patch_path)])
            if(target in self.libraries):
                target_number_of_bug_list.append((target, number_of_bugs))
        total_bugs = sum(i[1] for i in target_number_of_bug_list)
        target_list = target_number_of_bug_list

        rendering = template.render(target_list=target_list, total_bugs=total_bugs, fuzzer_list=self.fuzzers, plots_dir=self.plot_dir)

        self.path.write(output_file_name, rendering)
