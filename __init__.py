from binaryninja import PluginCommand
from .golang_parser import rename_functions, create_types, parse_go_file, print_files, comment_functions

PluginCommand.register(
    "golang\\auto-rename functions (gopclntab)",
    "Automatically rename go functions based on information from gopclntab",
    rename_functions)

PluginCommand.register(
    "golang\\Comment functions with filename (gopclntab)",
    "Comment the functions adding the filename where the function was defined",
    comment_functions)

PluginCommand.register(
    "golang\\Apply types",
    "Automatically apply type information",
    create_types)

PluginCommand.register(
    "golang\\Print file list",
    "Print on the console the list of files in the GoLang binary",
    print_files)

PluginCommand.register(
    "golang\\Parse GoLang executable",
    "Automatically apply all the transformation in the right order",
    parse_go_file)
