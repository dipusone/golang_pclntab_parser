import json

from binaryninja import PluginCommand, Settings
from .golang_parser import rename_functions, create_types, parse_go_file, print_files, comment_functions, create_type_at_address

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

PluginCommand.register_for_address(
    "golang\\Apply type at address",
    "Automatically apply type information starting from current address",
    create_type_at_address)


PluginCommand.register(
    "golang\\Print file list",
    "Print on the console the list of files in the GoLang binary",
    print_files)

PluginCommand.register(
    "golang\\Parse GoLang executable",
    "Automatically apply all the transformation in the right order",
    parse_go_file)

golang_settings = Settings()
golang_settings.register_group("golang_pclntab_parser", "Golang .pclntab Parser")
golang_version_prop = {
    "title": "Force Go Version",
    "type": "string",
    "enum": [
        "1.2",
        "1.16",
        "1.18",
        "1.20",
        "autodetect"
    ],
    "default": "autodetect",
    "description": "Go Version used to compile binary",
    "message": "Use this option to force a version if this fails (e.g. in an obfuscated binary).",
}
golang_settings.register_setting("golang_pclntab_parser.golangVersion", json.dumps(golang_version_prop))
