import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import jinja2
import os


# Two classes used to simplify the input for the rendering of the template
class FuzzerDescription:
    def __init__(self, name, type, use_case, availability, link):
        self.name = name
        self.type = type
        self.use_case = use_case
        self.availability = availability
        self.link = link


class Bug:
    def __init__(self, name, type, times):
        self.name = name
        self.type = type
        self.times = times


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


class FuzzerTemplate:
    TEMPLATES = "templates"
    OUTPUTS = "outputs"
    IMAGES = "images"
    BOX_PLOTS = "boxPlots"
    BAR_PLOTS = "barPlots"

    def __init__(self, directory_name):
        self.current_path = os.path.dirname(directory_name)
        # Set paths for templates, output and images
        self.template_dir = os.path.join(self.current_path, self.TEMPLATES)
        self.output_dir = os.path.join(self.current_path, self.OUTPUTS)
        self.image_dir = os.path.join(self.output_dir, self.IMAGES)
        self.box_plot_dir = os.path.join(self.output_dir, self.BOX_PLOTS)
        self.bar_plot_dir = os.path.join(self.output_dir, self.BAR_PLOTS)
        self.path = self.Path(self.template_dir, self.output_dir,
                              self.image_dir, self.box_plot_dir,
                              self.bar_plot_dir)
        # Set jinja environment
        self.jinjaEnv = jinja2.Environment(loader=jinja2.FileSystemLoader(
            self.template_dir))

    def render(self, file_name, output_file_name, fuzzer):
        # TODO Generate bugs reports, tables, graphs
        template = self.jinjaEnv.get_template(file_name)

        outputFile = os.path.join(self.output_dir, output_file_name)
        rendering = template.render(fuzzer=fuzzer)
        with open(outputFile, "w") as f:
            f.write(rendering)

    # Two functions to generate and save the plot (bar and box plot)
    def box_plot_figure(self, path, y_elts, x_elts):
        sns.boxplot(y=y_elts, x=x_elts)
        plt.savefig(path, format="svg")

    def bar_plot_figure(self, figure_name, path, x_pos, y_pos,
                        x_elts, y_elts, ylabel, title):
        plt.xticks(x_pos, x_elts)
        plt.bar(y_pos, y_elts, align="center", alpha=0.5)
        plt.ylabel(ylabel)
        plt.title(title)
        plt.savefig(path, format="svg")

    def csv_reading(self, file_name):
        return pd.read_csv(file_name, sep=',')

    def csv_interpretation(self, file_name):
        csv = self.csvReading(file_name)

#    def writeToFile(self):

    class Path:
        def __init__(self, template_dir, output_dir, image_dir,
                     box_plot_dir, bar_plot_dir):
            self.template_dir = template_dir
            self.output_dir = output_dir
            self.image_dir = image_dir
            self.box_plot_dir = box_plot_dir
            self.bar_plot_dir = bar_plot_dir

            # In case the directories don't exist
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(self.image_dir, exist_ok=True)
            os.makedirs(self.box_plot_dir, exist_ok=True)
            os.makedirs(self.bar_plot_dir, exist_ok=True)


# This code will be used in generateReport.py
fuzzer_template = FuzzerTemplate(__file__)

# for fuzzer in fuzzer_list:
#    fuzzer_template.render("template.html",
#                           fuzzer_descriptions[fuzzer])

fuzzer_template.render("fuzzerTemplate.html", "afl.html",
                       fuzzer_descriptions["afl"])
