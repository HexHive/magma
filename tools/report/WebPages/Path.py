import os
import jinja2


class Path:
    '''
    A class to represent the paths of the reports
    '''

    # The names of the directories
    TEMPLATES = "templates"
    OUTPUTS = "outputs"
    IMAGES = "images"
    TABLES = "tables"

    def __init__(self, template_dir, output_dir, tables_dir, plot_dir):
        # TODO CHange comments
        '''
        Parameters
        ----------
        template_dir:
            The directory where the fuzzer template is

        output_dir:
            The directory where to output the .html files

        image_dir:
            The directory where to output the generated images (svg format)

        plot_dir:
            The directory where to output the box plots

        tables_dir:
            The directory where to output the bar plots
        '''

        self.template_dir = template_dir
        self.output_dir = output_dir
        self.plot_dir = plot_dir
        self.tables_dir = tables_dir

        self.jinjaEnv = jinja2.Environment(loader=jinja2.FileSystemLoader(
            self.template_dir))

    def create_directories(self):
        # In case the directories don't exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.plot_dir, exist_ok=True)
        os.makedirs(self.tables_dir, exist_ok=True)

    def get_template(self, file_name):
        return self.jinjaEnv.get_template(file_name)

    def write(self, output_file_name, rendering):
        output_file = os.path.join(self.output_dir, output_file_name)

        with open(output_file, "w") as f:
            f.write(rendering)
