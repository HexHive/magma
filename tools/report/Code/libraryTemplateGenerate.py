from Code.Render import Render


class LibraryTemplate(Render):
    '''
        A class to represent a library
    '''

    LIBRARY_TEMPLATE = "library_template.html"

    def __init__(self, path):
        '''
        Parameters
        ----------
        path(Path):
            of class Path, used to have all the useful paths
        '''

        self.path = path
        self.template_dir = path.template_dir
        self.output_dir = path.output_dir
        self.tables_dir = path.tables_dir
        self.plot_dir = path.plot_dir

    def render(self, file_name, output_file_name, description):
        template = self.path.get_template(file_name)

        rendering = template.render(library_name=description)

        self.path.write(output_file_name, rendering)
