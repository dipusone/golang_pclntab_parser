from binaryninja import PluginCommand, Settings

from .parsers import (
    print_files,
    comment_functions,
    rename_functions,
    goresym_import,
    goresym_run_and_import,
    create_types,
    create_type_at_address,
    create_structures,
    create_structures_at_address,
    parse_go_file,
    parse_go_file_w_structures
)

PluginCommand.register(
    "golang\\Print file list",
    "Print on the console the list of files that were included in the Go binary",
    print_files)

PluginCommand.register(
    "golang\\Recover functions names",
    "Automatically recover and rename go functions based on information from gopclntab",
    rename_functions)

PluginCommand.register(
    "golang\\Import GoReSym",
    "Import information from GoReSym and restore the go version magic",
    goresym_import)

PluginCommand.register(
    "golang\\Run and Import GoReSym",
    "Run GoReSym, import the information and restore the go version magic",
    goresym_run_and_import)

PluginCommand.register(
    "golang\\Comment functions with source filename",
    "Comment the functions adding the full path of filename where the function was defined",
    comment_functions)

PluginCommand.register(
    "golang\\Recover Go types",
    "Parse the file, recover and create the go types definition",
    create_types)

PluginCommand.register_for_address(
    "golang\\Recover Go type at address",
    "Parse the current address, recover and create the go types definition",
    create_type_at_address)

PluginCommand.register(
    "golang\\Recover Binary Ninja types",
    "Parse the file, recover the go types definition and create Binary Ninja types",
    create_structures)

PluginCommand.register_for_address(
    "golang\\Recover Binary Ninja types at address",
    "Parse the current address, recover the go types definition and create Binary Ninja types",
    create_structures_at_address)

PluginCommand.register(
    "golang\\Parse Go executable",
    "Automatically parse the binary, rename and comment the functions and recover go types definition",
    parse_go_file)

PluginCommand.register(
    "golang\\Parse Go executable with Binary Ninja types",
    "Automatically parse the binary, rename and comment the functions and recover Binary Ninja types definition",
    parse_go_file_w_structures)


def setup_plugin_settings():
    settings = Settings()
    settings.register_group('golang_binary_parser', 'GoLang binary parser')
    Settings().register_setting("golang_binary_parser.components", """
        {
            "title" : "Organize in Components",
            "type" : "boolean",
            "default" : true,
            "description" : "Whether to organize the functions recovered in components or not",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.sanitize", """
        {
            "title" : "Sanitize names",
            "type" : "boolean",
            "default" : false,
            "description" : "Whether to remove . and spaces from the functions and type names (if you do not like using backticks)",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.minimum_name_length", """
        {
            "title" : "Function name minimum length",
            "type" : "number",
            "default" : 2,
            "description" : "Rename functions only if the their name length is greater then the value set",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)

    Settings().register_setting("golang_binary_parser.goresym_path", """
        {
            "title" : "GoReSym path",
            "type" : "string",
            "default" : "GoReSym",
            "description" : "Full path of GoReSym if it is not in your $PATH",
            "uiSelectionAction" : "file",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }
        """)


setup_plugin_settings()