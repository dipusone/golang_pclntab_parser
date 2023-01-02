from binaryninja import PluginCommand
from .golang_gopclntab_parser import rename_functions, create_types, parse_go_file

PluginCommand.register(
    "golang\\auto-rename functions (gopclntab)",
    "Automatically rename go functions based on information from gopclntab",
    rename_functions)

PluginCommand.register(
    "golang\\Apply types",
    "Automatically apply type information",
    create_types)

PluginCommand.register(
    "golang\\Parse GoLang executable",
    "Automatically apply all the transformation in the right order",
    parse_go_file)