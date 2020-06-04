from Render import Render


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

        link (string):
            The link to the repository of the fuzzer
        '''

        self.name = name
        self.type = type
        self.use_case = use_case
        self.availability = availability
        self.link = link


# We initialize all different descriptions
fuzzer_descriptions = {
    "afl": FuzzerDescription("AFL", "Gray-box binary fuzzer",
                             "Mutational fuzzing", "Open-source",
                             "https://github.com/google/AFL"),

    "aflplusplus": FuzzerDescription("AFLPlusPlus", "Gray-box binary fuzzer",
                                     "Mutational fuzzing", "Open-source",
                                     "https://github.com/google/AFL"),

    "aflfast": FuzzerDescription("AflFast", "Gray-box binary fuzzer",
                                 "Mutational fuzzing", "Open-source",
                                 "https://github.com/mboehme/aflfast"),

    "fairfuzz": FuzzerDescription("FairFuzz", "Gray-box binary fuzzer",
                                  "Mutational fuzzing", "Open-source",
                                  "https://github.com/carolemieux/afl-rb"),

    "honggfuzz": FuzzerDescription("HonggFuzz", "Gray-box binary fuzzer",
                                   "Mutational fuzzing", "Open-source",
                                   "https://honggfuzz.dev"),

    "moptafl": FuzzerDescription("Moptafl", "Gray-box binary fuzzer",
                                 "Mutational fuzzing", "Open-source",
                                 "https://github.com/puppet-meteor/MOpt-AFL"),

    "vanilla": FuzzerDescription("Vanilla", "", "", "", "")
}


class FuzzerTemplate(Render):
    '''
    A class to generate a template for a fuzzer. It generate its html file and 
    its plots
    '''

    FUZZER_TEMPLATE = "fuzzerTemplate.html"

    def __init__(self, path, libraries):
        '''
        Parameters
        ----------
        path (Path):
            of class Path, used to have all the useful paths

        libraries (array of string):
            libraries
        '''

        super(FuzzerTemplate, self).__init__(path)

        self.libraries = libraries
        self.plot_dir = self.path.plot_dir
        # Set paths for templates, output and image

    def render(self, file_name, output_file_name):
        '''
        Generate (write to html file) and render reports (html, bugs reports,
        tables,...)

        Parameters
        ----------
        file_name (string):
            The file to get the directory from

        output_file_name (string):
            The name of the html file to write to. (example: "afl.html")
        '''

        # We split to get the name (e.g we get afl from "afl.html")
        splitted_output_file_name = output_file_name.split(".")

        description = fuzzer_descriptions[splitted_output_file_name[0]]

        template = self.path.get_template(file_name)

        rendering = template.render(fuzzer=description,
                                    libraries=self.libraries,
                                    choices=["bar", "box"],
                                    reached_triggered=["reached", "triggered"],
                                    plot_dir=self.plot_dir)

        # We write what we have generated
        self.path.write(output_file_name, rendering)
