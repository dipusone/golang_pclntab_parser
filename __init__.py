from binaryninja import PluginCommand
from .golang_gopclntab_parser import rename_functions

PluginCommand.register(
    "golang\\auto-rename functions (gopclntab)",
    "Automatically rename go functions based on information from gopclntab",
    rename_functions)
