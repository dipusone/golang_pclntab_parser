from binaryninja import Symbol, SymbolType, Settings

from ..internal_types.datatypes import GoVersion

from .common import (
    GoHelper,
    log_error,
    log_info,
    log_debug,
    log_warn,
    santize_gofunc_name,
    make_component_from_gofunc_name,
    add_to_component
)


class FunctionRenamer(GoHelper):

    def rename_functions(self):
        min_function_name_len = Settings().get_integer('golang_binary_parser.minimum_name_length')

        try:
            self.init_gopclntab()
        except ValueError:
            log_error("Golang version not supported")
            return

        log_info("renaming functions based on .gopclntab section")
        log_info(f"gopclntab contains {self.gopclntab.nfunctab} functions")

        renamed = 0
        created = 0

        for fidx in range(self.gopclntab.nfunctab):
            if self.gopclntab.version == GoVersion.ver12:
                function = self.gopclntab.go12FuncInfo(fidx)
            else:
                function = self.gopclntab.funcInfo(fidx)
            function_addr, name = function.entry, function.resolvedName
            log_debug(f"Found function at 0x{function_addr:x} with name {name}")

            func = self.bv.get_function_at(function_addr)
            if not func:
                func = self.bv.create_user_function(function_addr)
                created += 1

            # if the function is outside the .text range (which should not happen, but you never know, ignore it)
            if not func:
                log_debug(f"The function {name} at 0x{function_addr:x} not backed by the file")
                continue

            if name and len(name) > min_function_name_len:
                name = santize_gofunc_name(name)
                sym = Symbol(SymbolType.FunctionSymbol,
                             function_addr,
                             name,
                             name)
                self.bv.define_user_symbol(sym)
                component_name = make_component_from_gofunc_name(name)
                add_to_component(self.bv, component_name, func)
                renamed += 1
            else:
                log_warn(f"not using function name {name} for function at {hex(function_addr)} which is '{name}'")

        log_info(f"Created {created} functions")
        log_info(f"Renamed {renamed - created} functions")
        log_info(f"Total {renamed} functions")
        self.bv.update_analysis_and_wait()

    def run(self):
        return self.rename_functions()


class FunctionCommenter(GoHelper):
    OVERRIDE_COMMENT = True
    COMMENT_KEY = "File:"

    def comment_functions(self):
        try:
            self.init_gopclntab()
        except ValueError:
            log_error("Golang version not supported")
            return

        log_info("Commenting functions based on .gopclntab section")
        log_info(f"gopclntab contains {self.gopclntab.nfunctab} functions")

        commented = 0

        for fidx in range(self.gopclntab.nfunctab):
            if self.gopclntab.version == GoVersion.ver12:
                function = self.gopclntab.go12FuncInfo(fidx)
            else:
                function = self.gopclntab.funcInfo(fidx)
            function_addr = function.entry

            func = self.bv.get_function_at(function_addr)
            # Parse only already existing functions
            if not func:
                continue

            filename = self.gopclntab.pc2filename(function)
            if not filename:
                continue

            if not self.OVERRIDE_COMMENT and func.comment:
                log_debug("Already commented, skipping")
                continue

            comment = f"{self.COMMENT_KEY} {filename.decode('utf-8')}"
            func.comment = comment
            commented += 1

        log_info(f"Commented {commented} functions")

    def run(self):
        return self.comment_functions()
