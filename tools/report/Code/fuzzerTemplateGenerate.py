from Code.Path import Path
from Code.Render import Render

import os # TODO Shouldn't be needed


# Two classes used to simplify the input for the rendering of the template
class FuzzerDescription:
    '''
    A class to represent a fuzzer and its description
    '''

    def __init__(self, name, type, use_case, availability, link):
        '''
        Parameters
        ----------
        name (string):
            The name of the fuzzer (e.g."AFL", "AFL++")

        type (string):
            The type of the fuzzer (e.g. "gray-box")

        use_case (string):
            Mutational fuzzing or generational fuzzing

        availability (string):
            Indicates if it is open source or not
        '''

        self.name = name
        self.type = type
        self.use_case = use_case
        self.availability = availability
        self.link = link


fuzzer_descriptions = {
    "afl": FuzzerDescription("AFL", "Gray-box binary fuzzer",
                             "Mutational fuzzing", "Open-source",
                             "https://github.com/google/AFL"),

    "aflplusplus": FuzzerDescription("AFL++", "Gray-box binary fuzzer",
                                     "Mutational fuzzing", "Open-source",
                                     "https://github.com/google/AFL"),

    "aflfast": FuzzerDescription("AFLFast", "Gray-box binary fuzzer",
                                 "Mutational fuzzing", "Open-source",
                                 "https://github.com/mboehme/aflfast"),

    "fairfuzz": FuzzerDescription("FairFuzz", "Gray-box binary fuzzer",
                                  "Mutational fuzzing", "Open-source",
                                  "https://github.com/carolemieux/afl-rb"),

    "honggfuzz": FuzzerDescription("HongFuzz", "Gray-box binary fuzzer",
                                   "Mutational fuzzing", "Open-source",
                                   "https://honggfuzz.dev"),

    "moptafl": FuzzerDescription("Mopt-AFL", "Gray-box binary fuzzer",
                                 "Mutational fuzzing", "Open-source",
                                 "https://github.com/puppet-meteor/MOpt-AFL"),

    "vanilla": FuzzerDescription("Vanilla", "", "", "", "")
}


class FuzzerTemplate(Render):
    '''
    A class to generate a template for a fuzzer. Generate its html file and its
    plots
    '''

    FUZZER_TEMPLATE = "fuzzerTemplate.html"

    def __init__(self, path):
        '''
        Parameters
        ----------
        path(Path):
            of class Path, used to have all the useful paths

        _file_:
            The file to get the directory from
        '''

        super(FuzzerTemplate, self).__init__(path)
        # Set paths for templates, output and images
        self.template_dir = path.template_dir
        self.output_dir = path.output_dir
        self.tables_dir = path.tables_dir
        self.plot_dir = path.plot_dir

    def render(self, file_name, output_file_name):
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

        splitted_output_file_name = output_file_name.split(".")

        description = fuzzer_descriptions[splitted_output_file_name[0]]
        # TODO Generate bugs reports, tables, graphs
        template = self.path.get_template(file_name)

        rendering = template.render(fuzzer=description)

        self.path.write(output_file_name, rendering)


# TODO Delete below
TEMPLATES = "templates"
OUTPUTS = "outputs"
PLOTS = "plots"
TABLES = "tables"

current_path = os.path.dirname(__file__)
# Set paths for templates, output and images
output_dir = os.path.join(current_path, OUTPUTS)
template_dir = os.path.join(current_path, TEMPLATES)
plot_dir = os.path.join(output_dir, PLOTS)
tables_dir = os.path.join(output_dir, TABLES)
path = Path(template_dir, output_dir, tables_dir, plot_dir)
# This code will be used in generateReport.py
fuzzer_template = FuzzerTemplate(path)

# for fuzzer in fuzzer_list:
#     fuzzer_template.render("template.html",
#                            fuzzer_descriptions[fuzzer])

fuzzer_template.render("fuzzerTemplate.html", "afl.html")
