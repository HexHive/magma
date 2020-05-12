from Render import Render


class LibraryDescription:
    '''
    A class to represent a library and its description
    '''

    def __init__(self, name, availability, link):
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
        self.availability = availability
        self.link = link


library_descriptions = {
    "libpng": LibraryDescription("Libpng",
                                 "Open-source",
                                 "https://github.com/glennrp/libpng"),

    "libtiff": LibraryDescription("Libtiff",
                                  "Open-source",
                                  "https://github.com/vadz/libtiff/tree/master/libtiff"),

    "libxml2": LibraryDescription("Libxml2",
                                  "Open-source",
                                  "https://github.com/GNOME/libxml2"),

    "openssl": LibraryDescription("Openssl",
                                  "Open-source",
                                  "https://github.com/openssl/openssl"),

    "php": LibraryDescription("Php",
                              "Open-source",
                              "https://github.com/php/php-src"),

    "poppler": LibraryDescription("Poppler",
                                  "Open-source",
                                  "https://github.com/freedesktop/poppler"),

    "sqlite3": LibraryDescription("Sqlite3",
                                  "Open-source",
                                  "https://github.com/sqlite/sqlite"),



}


class LibraryTemplate(Render):
    LIBRARY_TEMPLATE = "library_template.html"
    '''
        A class to represent a library
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
        super(LibraryTemplate, self).__init__(path)
        self.template_dir = path.template_dir
        self.output_dir = path.output_dir
        self.tables_dir = path.tables_dir
        self.plot_dir = path.plot_dir

    def render(self, file_name, output_file_name):
        template = self.path.get_template(file_name)
        splitted_output_file_name = output_file_name.split(".")

        rendering = template.render(library=library_descriptions[splitted_output_file_name[0]])

        self.path.write(output_file_name, rendering)
