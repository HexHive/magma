from libraryTemplateGenerate import LibraryTemplate
from Path import Path
from mainPageTemplateGenerate import MainPageTemplate
import os



TEMPLATES = "templates"
OUTPUTS = "outputs"
PLOTS = "plots"
TABLES = "tables"
LIBRARIES = "libraries"

current_path = os.path.dirname(__file__)
# Set paths for templates, output and images
output_dir = os.path.join(current_path, OUTPUTS)
libraries_dir = os.path.join(output_dir,LIBRARIES)
template_dir = os.path.join(current_path, TEMPLATES)
plot_dir = os.path.join(output_dir, PLOTS)
tables_dir = os.path.join(output_dir, TABLES)



library_template = LibraryTemplate(Path(template_dir,libraries_dir,tables_dir,plot_dir))
main_template = MainPageTemplate(Path(template_dir,output_dir,tables_dir,plot_dir),["afl"],["php"])




library_template.render("library_template.html","libpng.html")
main_template.render("report_template.html","report.html")