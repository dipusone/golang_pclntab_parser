import binaryninja as bn
import json
import subprocess

from binaryninja import BinaryView, interaction, Symbol, SymbolType
from tempfile import NamedTemporaryFile

from ..internal_types.datatypes import GoVersion

from .common import (
    NAME,
    log_error,
    log_info,
    log_debug,
    santize_gofunc_name,
    make_component_from_gofunc_name,
    add_to_component
)


class GoReSymImporter(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv: BinaryView, file: str = None):
        super().__init__(NAME, True)
        self.bv = bv
        self.file = file or interaction.get_open_filename_input('GoReSym JSON file')

    def run(self):
        try:
            with open(self.file) as json_file:
                data = json.loads(json_file.read())
        except:
            log_error(f"Unable to load GoReSym JSON file: {self.file}")
            return

        goresym_magic_address = data['TabMeta']['VA']
        goresym_version = data['TabMeta']['Version']
        log_info(f"Go version: {goresym_version}")

        go_version = GoVersion.from_string(goresym_version)
        if go_version != GoVersion.invalid:
            go_magic = GoVersion.to_magic(go_version)
            log_debug(f"Setting go magic to {go_magic} at address 0x{goresym_magic_address:X}")
            self.bv.write(goresym_magic_address, go_magic)

        log_info("renaming functions based on GoReSym output")

        renamed = 0
        created = 0

        for user_function in data['UserFunctions']:
            function_addr = user_function['Start']
            name = user_function['FullName']

            log_debug(f"Got function at 0x{function_addr:x} with name {name}")

            func = self.bv.get_function_at(function_addr)
            if not func:
                func = self.bv.create_user_function(function_addr)
                created += 1

            # if the function is outside the .text range (which should not happen, but you never know, ignore it)
            if not func:
                log_debug(f"The function {name} at 0x{function_addr:x} not backed by the file")
                continue

            name = santize_gofunc_name(name)
            sym = Symbol(SymbolType.FunctionSymbol,
                         function_addr,
                         name,
                         name)
            self.bv.define_user_symbol(sym)
            component_name = make_component_from_gofunc_name(name)
            add_to_component(self.bv, component_name, func)
            renamed += 1

        log_info(f"Created {created} functions")
        log_info(f"Renamed {renamed - created} functions")
        log_info(f"Total {renamed} functions")
        self.bv.update_analysis_and_wait()


class GoResSymExecutor(GoReSymImporter):

    def __init__(self, bv: BinaryView):
        self.__output_file = NamedTemporaryFile()
        log_debug(f"Saving output to file {self.__output_file.name}")
        super().__init__(bv, self.__output_file.name)

    def run(self):
        goresym_path = bn.Settings().get_string('golang_binary_parser.goresym_path')

        go_file = NamedTemporaryFile()
        self.bv.file.raw.save(go_file.name)
        go_file.flush()
        subprocess.run([goresym_path, go_file.name],
                       stdout=self.__output_file,
                       stderr=subprocess.DEVNULL)
        self.__output_file.flush()

        super().run()
