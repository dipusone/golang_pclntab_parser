import binaryninja as bn
import struct

from binaryninja import Symbol, SymbolType

from .binaryninja_types import *
from .types import *

NAME = 'Golang Loader Helper'
GoFixLogger = bn.Logger(0, NAME)

log_debug = GoFixLogger.log_debug
log_info = GoFixLogger.log_info
log_warn = GoFixLogger.log_warn
log_error = GoFixLogger.log_error


log_debug = log_info


def santize_gofunc_name(name):
    name = name.replace(" ", "")
    name = name.replace('.', '_')
    return name


def sanitize_gotype_name(name):
    name = santize_gofunc_name(name)
    return name


class GoHelper(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv: bn.BinaryView, name: str = None):
        name = f"{NAME} ({name})" if name else NAME
        super().__init__(name, True)
        self.bv = bv
        self.br = bn.binaryview.BinaryReader(bv)
        # Consider caching the table as class variable
        self.gopclntab = self.init_gopclntab()

    def init_gopclntab(self):
        gopclntab = self.get_section_by_name(".gopclntab")
        if gopclntab:
            start_addr = gopclntab.start
            end_addr = gopclntab.end
        else:
            log_debug("Failed to find .gopclntab section")
            for go_magic in [go12magic, go116magic, go118magic, go120magic]:
                start_addr = self.bv.find_next_data(0, go_magic)
                if start_addr is None:
                    continue
                # We do not have an end, suppose the end of the allocated range
                for allocated_range in self.bv.allocated_ranges:
                    if start_addr in allocated_range:
                        end_addr = allocated_range.end
                        break
                else:
                    log_error(f"Failed to find the end for .gopclntab found at {hex(start_addr)}")
                    return
                log_debug(f"Found .gopclntab at {hex(start_addr)}")
                break
            else:
                log_error("Failed to find section .gopclntab")
                return

        self.gopclntab = GoPclnTab(start_addr,
                                   end_addr,
                                   self.bv[start_addr:end_addr]
                                   )
        log_debug(f"Found .gopclntab at {hex(start_addr)}")
        log_debug(f"Found .gopclntab  {self.gopclntab}")
        log_info(f"gopclntab version is {self.gopclntab.version}")

        if self.gopclntab.version != GoVersion.ver12:
            # Version of go different from 12 need to know the text start to calculate the function entry
            text = self.get_section_by_name('.text')

            if not text:
                log_error("Unable to find .text section")
                return
            self.gopclntab.textStart = text.start

        self.gopclntab.quantum = self.gopclntab.get_byte_at(6)
        self.gopclntab.ptrsize = self.gopclntab.get_byte_at(7)

        if self.gopclntab.ptrsize not in self.gopclntab.valid_ptr_sizes:
            log_error(f"Invalid ptrsize: it is {self.gopclntab.ptrsize} " +
                      f"but should be in {self.gopclntab.valid_ptr_sizes}")
            return

        self.gopclntab.nfunctab = int(self.gopclntab.offset(0))
        self.gopclntab.nfiletab = int(self.gopclntab.offset(1))
        functabFieldSize = self.gopclntab.functabFieldSize()

        # It should be possible to restrict the size of funcdata by considering the offset of the first function
        if self.gopclntab.version in (GoVersion.ver118, GoVersion.ver120):
            self.gopclntab.funcnametab = self.gopclntab.range(3, 4)  # This contains the names of the functions
            self.gopclntab.cutab = self.gopclntab.range(4, 5)
            self.gopclntab.filetab = self.gopclntab.range(5, 6)
            self.gopclntab.pctab = self.gopclntab.range(6, 7)
            self.gopclntab.funcdata = self.gopclntab.data(7)  # This is where the functions info are
            self.gopclntab.functab = self.gopclntab.data(7)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functabFieldSize
            self.gopclntab.functab = self.gopclntab.functab[:self.gopclntab.functabsize]
        elif self.gopclntab.version == GoVersion.ver116:
            self.gopclntab.funcnametab = self.gopclntab.range(2, 3)
            self.gopclntab.cutab = self.gopclntab.range(3, 4)
            self.gopclntab.filetab = self.gopclntab.range(4, 5)
            self.gopclntab.pctab = self.gopclntab.range(5, 6)
            self.gopclntab.funcdata = self.gopclntab.data(6)
            self.gopclntab.functab = self.gopclntab.data(6)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functabFieldSize
            self.gopclntab.functab = self.gopclntab.functab[:self.gopclntab.functabsize]
        elif self.gopclntab.version == GoVersion.ver12:
            # Not all but it is enough to rename the functions
            self.gopclntab.nfunctab = self.gopclntab.uintptr(8)
            self.gopclntab.funcdata = self.gopclntab.raw
            self.gopclntab.funcnametab = self.gopclntab.raw
            self.gopclntab.pctab = self.gopclntab.raw
            self.gopclntab.functab = self.gopclntab.data_after_offset(8 + self.gopclntab.ptrsize)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functabFieldSize
            fileoff = struct.unpack("I",
                                    self.gopclntab.functab[self.gopclntab.functabsize:self.gopclntab.functabsize + 4])[0]
            self.gopclntab.functab = self.gopclntab.functab[:self.gopclntab.functabsize]
            self.gopclntab.filetab = self.gopclntab.data_after_offset(fileoff)
            self.gopclntab.nfiletab = struct.unpack("I", self.gopclntab.filetab[:4])[0]
            self.gopclntab.filetab = self.gopclntab.filetab[:(self.gopclntab.nfiletab + 1) * 4]

        else:
            raise ValueError("Invalid go version")

    def get_section_by_name(self, section_name):
        if section_name in self.bv.sections:
            return self.bv.sections[section_name]
        else:
            return None

    def get_pointer_at_virt(self, addr, size=None):
        size = size or self.ptr_size
        x = self.bv.read(addr, size)
        if len(x) == 8:
            return struct.unpack("Q", x)[0]
        elif len(x) == 4:
            return struct.unpack("I", x)[0]
        else:
            raise ValueError("Invalid size {} for pointer; data: {!r}"
                             .format(len(x), x))

    def get_pointer_at(self, at_addr, size=None):
        self.br.seek(at_addr)
        if size is None:
            size = self.ptr_size

        if size == 8:
            return self.br.read64()
        elif size == 4:
            return self.br.read32()
        else:
            raise ValueError("Unsupported ptr_size: {!r}".format(size))

    def get_function_around(self, addr):
        bbl = self.bv.get_basic_blocks_at(addr)
        if not bbl:
            return None
        bb = bbl[0]
        if not bb:
            return None
        return bb.function

    @property
    def ptr_size(self):
        return self.gopclntab.ptrsize

    def quick_go_version(self) -> GoVersion:
        if self.gopclntab is None:
            self.init_gopclntab()
        gopclntab = self.gopclntab
        start_addr = gopclntab.start
        return GoVersion.from_magic(self.bv[start_addr:start_addr + 6])

    def read_varint(self, start_addr: int) -> (int, int):
        shift = 0
        result = 0
        read = 0
        while True:
            i = self.bv.read(start_addr + read, 1)[0]
            result |= (i & 0x7f) << shift
            shift += 7
            read += 1
            if not (i & 0x80):
                break
        return result, read


class FunctionRenamer(GoHelper):
    MIN_FUNCTION_NAME = 2

    def rename_functions(self):
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
            log_debug(f"Found function at {hex(function_addr)} with name {name}")

            func = self.bv.get_function_at(function_addr)
            if not func:
                self.bv.create_user_function(function_addr)
                created += 1

            if name and len(name) > self.MIN_FUNCTION_NAME:
                # Don't rename functions which already have the correct name
                if func.name != name:
                    name = santize_gofunc_name(name)
                    sym = Symbol(SymbolType.FunctionSymbol,
                                 function_addr,
                                 name,
                                 name)
                    self.bv.define_user_symbol(sym)
                    renamed += 1
            else:
                log_warn(f"not using function name {name} for function at {hex(function_addr)}")

        log_info(f"Created {created} functions")
        log_info(f"Renamed {renamed - created} functions")
        log_info(f"Total {renamed} functions")
        self.bv.update_analysis_and_wait()

    def run(self):
        return self.rename_functions()


class PrintFiles(GoHelper):

    def print_files(self):
        try:
            self.init_gopclntab()
        except ValueError:
            log_error("Golang version not supported")
            return

        for fidx in range(self.gopclntab.nfiletab):
            file_name = self.gopclntab.fileName(fidx)
            log_info(file_name.decode('utf-8'))

    def run(self):
        return self.print_files()


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


class TypeParser(GoHelper):
    TYPES = [
        GO_KIND,
        GOLANG_TYPE,
    ]

    TYPED = [
        'runtime.newobject',
        'runtime.makechan',
        'runtime.makemap',
        'runtime.mapiterinit',
        'runtime.makeslice'
    ]

    MAX_TYPE_LENGHT = 40

    def __init__(self, bv: bn.BinaryView, name: str = None, target: int = None):
        super().__init__(bv, name)
        self.target = target

    def create_types(self):
        log_info(f"Creating reference types")
        go_version = self.quick_go_version()
        log_debug(f"Go Version is {go_version}")

        already_parsed = set()
        data_vars = []
        created = 0

        for segment_name in ('.rodata', '__rodata'):
            rodata = self.get_section_by_name(segment_name)
            if rodata:
                break
        else:
            log_error("Unable to find any rodata sections. Terminating")
            return

        for go_type in self.TYPES:
            name, type_str = go_type
            new_type = self.bv.parse_type_string(type_str)
            if len(new_type) == 0:
                log_warn(f"Unable to parse type string {name}")
                continue
            self.bv.define_user_type(name, new_type[0])

        golang_type = self.bv.get_type_by_name(GOLANG_TYPE[0])

        if self.target:
            data_vars.append((self.target, 0))
        else:
            data_vars = self.collect_xrefs(golang_type)

        while len(data_vars) > 0:
            data_var_addr, parent = data_vars.pop(0)
            go_data_type = self.bv.get_data_var_at(data_var_addr)
            # get_data_var_at will return None on error
            # funny enough `not <void var>` is `True`
            if go_data_type is None:
                go_data_type = self.bv.define_user_data_var(data_var_addr, golang_type)
            if data_var_addr in already_parsed:
                log_debug(f"Skipping already parsed at 0x{data_var_addr:x}")

            go_data_type.type = golang_type
            # TODO figure out why sometimes the type info are not there
            # the next portion of code might fail
            # name_offset = go_data_type.value['nameoff']
            # so use a custom dataclass instead
            try:
                gotype = GolangType.from_bv(self.bv,
                                            go_data_type.address,
                                            rodata.start,
                                            go_version
                                            )
                type_name = TypeName.from_bv(self.bv,
                                             gotype.resolved_name_addr,
                                             go_version
                                             )
            except:
                continue
            name = type_name.name
            if not name or len(name) == 0:
                log_debug("Invalid Name, skipping")
                continue

            log_debug(f"Found name at 0x{gotype.resolved_name_addr:x} with value {name}")

            sanitazed_name = sanitize_gotype_name(name)
            go_data_type.name = f"{sanitazed_name}_type"
            # add cross-reference for convenience
            self.bv.add_user_data_ref(
                gotype.address_off('nameOff'),
                gotype.resolved_name_addr)

            if parent:
                self.bv.add_user_data_ref(
                    parent,
                    data_var_addr
                )

            name_datavar = self.bv.get_data_var_at(gotype.resolved_name_addr)
            name_datavar.name = f"{go_data_type.name}_name"

            # get any type referencing this type
            if gotype.typeOff != 0x0:
                log_debug("Found type pointing to this type, adding to set to see")
                log_debug(f"Dest will be {gotype.resolved_type_off}")
                data_vars.insert(0, (gotype.resolved_type_off, gotype.address_off('typeOff')))

            already_parsed.add(data_var_addr)
            created += 1

        log_info(f"Created {created} types")

    def collect_xrefs(self, golang_type: bn.Type) -> list:
        data_vars = []
        log_info("Searching for functions accessing type objects")
        log_info(f"Will search for {len(self.TYPED)} functions")

        for typed_function in self.TYPED:
            functions = self.bv.get_functions_by_name(typed_function)
            if not functions:
                # maybe the name were generated by `FunctionRenamer` and therefore sanitized
                sanitazed_typed_function = santize_gofunc_name(typed_function)
                functions = self.bv.get_functions_by_name(sanitazed_typed_function)

            for function in functions:
                log_info(f"Parsing function {function.name}")
                ptr_var = function.parameter_vars[0]
                ptr_var.type = bn.Type.pointer(self.bv.arch, golang_type)
                log_debug(f"Parsing xrefs to {function.name}")

                # Collect direct references, since after we have to expand the list
                # with the references from typeoff
                for caller_site in function.caller_sites:
                    try:
                        mlil = caller_site.mlil
                    except:
                        log_debug("Unable to get the mlil for instruction")
                        continue
                    if not mlil or mlil.operation != bn.MediumLevelILOperation.MLIL_CALL:
                        log_debug(f"Callsite at 0x{mlil.address:x} is not a call, skipping")
                        continue
                    data_vars.append((mlil.params[0].value.value, 0))
        return data_vars

    def run(self):
        return self.create_types()


class RunAll(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__(NAME, True)
        self.bv = bv
        self.analysis = []
        self.analysis.append(FunctionRenamer(bv))
        self.analysis.append(FunctionCommenter(bv))
        self.analysis.append(TypeParser(bv))

    def run(self):
        for analysis in self.analysis:
            analysis.start()
            analysis.join()
        log_info(f"Terminated all analysis")


def rename_functions(bv):
    helper = FunctionRenamer(bv)
    return helper.start()


def create_types(bv):
    helper = TypeParser(bv)
    return helper.start()


def create_type_at_address(bv, address):
    helper = TypeParser(bv, target=address)
    return helper.start()


def print_files(bv):
    helper = PrintFiles(bv)
    return helper.start()


def comment_functions(bv):
    helper = FunctionCommenter(bv)
    return helper.start()


def parse_go_file(bv: bn.BinaryView):
    ra = RunAll(bv)
    return ra.start()
