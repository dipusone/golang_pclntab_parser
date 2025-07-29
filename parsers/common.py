import functools

import binaryninja as bn
import struct
import warnings

from binaryninja import redirect_output_to_log, BinaryView, Function
from typing import List
from uuid import uuid4

from ..internal_types.datatypes import GoMagics, GoPclnTab, GoVersion

NAME = 'Golang Loader Helper'
GoFixLogger = bn.Logger(0, NAME)
log_debug = GoFixLogger.log_debug
log_info = GoFixLogger.log_info
log_warn = GoFixLogger.log_warn
log_error = GoFixLogger.log_error

# force logging to debug
DEBUG = False

if DEBUG:
    log_debug = log_info
redirect_output_to_log()

warnings.filterwarnings("ignore", category=DeprecationWarning)


def santize_gofunc_name(name):
    if bn.Settings().get_bool('golang_binary_parser.sanitize'):
        name = name.replace(" ", "")
        name = name.replace('.', '_')
    return name


def sanitize_gotype_name(name: str):
    name = santize_gofunc_name(name)
    if name.startswith('*'):
        name = name[1:]
    return name


def make_component_from_gofunc_name(name: str) -> List[str]:
    if not bn.Settings().get_bool('golang_binary_parser.components'):
        return []

    # There are some special cases like  : and [...]
    # replace them with a placeholder before split
    specials = (
        (':', str(uuid4())),
        ('[...]', str(uuid4()))
    )

    for k, p in specials:
        name = name.replace(k, p)

    name = name.replace('.', '/')

    end = len(name)
    # we do not want to split for dots in {} or []
    # find the lower index of { or [
    for c in ('{', '['):
        tend = name.find(c, 0, end)
        if tend > 0:
            end = tend
    splits = name.count('/', 0, end)

    result = []
    # Substitute back the specials chars
    for token in name.split('/', splits):
        for k, p in specials:
            token = token.replace(p, k)
        result.append(token)
    # Return everything a part from the last token which is the function name
    return result[:-1]


def add_to_component(bv: BinaryView, module: List[str], fn: Function):
    if not module:
        return
    component = None
    full_path = None

    parent = None
    for m in module:
        full_path = "/".join([full_path, m]) if full_path else m
        component = bv.get_component_by_path(full_path)

        if not component:
            component = bv.create_component(m, parent)

        parent = component

    component.add_function(fn)


class GoHelper(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv: bn.BinaryView, name: str = None):
        name = f"{NAME} ({name})" if name else NAME
        super().__init__(name, True)
        self.bv = bv
        self.br = bn.binaryview.BinaryReader(bv)
        # TODO Consider caching the table as class variable
        self.gopclntab = self.init_gopclntab()

    def init_gopclntab(self):

        gopclntab = self.get_section_by_name(".gopclntab")

        if gopclntab:
            start_addr = gopclntab.start
            end_addr = gopclntab.end
        else:
            log_debug("Failed to find .gopclntab section")
            for go_magic in GoMagics.all():
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
        log_debug(f"Found .gopclntab  {hex(self.gopclntab.start)}")
        log_info(f"gopclntab version is {self.gopclntab.version}")

        if self.gopclntab.version != GoVersion.ver12:
            # Version of go different from 12 need to know the text start to calculate the function entry

            for segment_name in ('.text', '__text'):
                text = self.get_section_by_name(segment_name)
                if text:
                    break
            else:
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
        functab_field_size = self.gopclntab.functabFieldSize()

        # It should be possible to restrict the size of funcdata by considering the offset of the first function
        # https://github.com/golang/go/blob/2c358ffe9762ba08c8db0196942395f97775e31b/src/debug/gosym/pclntab.go#L254
        if self.gopclntab.version in (GoVersion.ver118, GoVersion.ver120):
            self.gopclntab.funcnametab = self.gopclntab.range(3, 4)  # This contains the names of the functions
            self.gopclntab.cutab = self.gopclntab.range(4, 5)
            self.gopclntab.filetab = self.gopclntab.range(5, 6)
            self.gopclntab.pctab = self.gopclntab.range(6, 7)
            self.gopclntab.funcdata = self.gopclntab.data(7)  # This is where the functions info are
            self.gopclntab.functab = self.gopclntab.data(7)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functab_field_size
            self.gopclntab.functab = self.gopclntab.functab[:self.gopclntab.functabsize]
        elif self.gopclntab.version == GoVersion.ver116:
            self.gopclntab.funcnametab = self.gopclntab.range(2, 3)
            self.gopclntab.cutab = self.gopclntab.range(3, 4)
            self.gopclntab.filetab = self.gopclntab.range(4, 5)
            self.gopclntab.pctab = self.gopclntab.range(5, 6)
            self.gopclntab.funcdata = self.gopclntab.data(6)
            self.gopclntab.functab = self.gopclntab.data(6)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functab_field_size
            self.gopclntab.functab = self.gopclntab.functab[:self.gopclntab.functabsize]
        elif self.gopclntab.version == GoVersion.ver12:
            # Not all but it is enough to rename the functions
            self.gopclntab.nfunctab = self.gopclntab.uintptr(8)
            self.gopclntab.funcdata = self.gopclntab.raw
            self.gopclntab.funcnametab = self.gopclntab.raw
            self.gopclntab.pctab = self.gopclntab.raw
            self.gopclntab.functab = self.gopclntab.data_after_offset(8 + self.gopclntab.ptrsize)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functab_field_size
            fileoff = struct.unpack("I",
                                    self.gopclntab.functab[self.gopclntab.functabsize:self.gopclntab.functabsize + 4])[
                0]
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
            raise ValueError(f"Unsupported ptr_size: {size}")

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


def time_it(func):
    @functools.wraps(func)
    def wrapped_function(*args, **kwargs):
        import time  # I do not like to import in functions, but the import is needed only in debug
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        log_debug(f"Execution time of {func} {end_time - start_time}")
        return result


    return wrapped_function
