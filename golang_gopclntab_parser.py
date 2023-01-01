import binaryninja as bn
import dataclasses
import struct

from binaryninja import Symbol, SymbolType
from dataclasses import dataclass
from enum import IntEnum
from operator import attrgetter

NAME = 'Golang Loader Helper'
GoFixLogger = bn.Logger(0, NAME)


log_debug = GoFixLogger.log_debug 
log_info = GoFixLogger.log_info
log_warn = GoFixLogger.log_warn
log_error = GoFixLogger.log_error


go12magic  = b"\xfb\xff\xff\xff\x00\x00"
go116magic = b"\xfa\xff\xff\xff\x00\x00"
go118magic = b"\xf0\xff\xff\xff\x00\x00"
go120magic = b"\xf1\xff\xff\xff\x00\x00"


class GoVersion(IntEnum):
    invalid = -1
    ver11 = 11
    ver12 = 12
    ver116 = 116
    ver118 = 118
    ver120 = 120

    @classmethod
    def from_magic(cls, magic):
        assert len(magic) == 6
        if magic == go12magic:
            return cls.ver12
        elif magic == go116magic:
            return cls.ver116
        elif magic == go118magic:
            return cls.ver118
        elif magic == go120magic:
            return cls.ver120
        return cls.invalid


@dataclass
class LineTableEntry:
    field_size: int
    raw: bytes

    ptrsize: int = 4

    def __init__(self, ptrsize: int = 4, functabFieldSize: int = 4, raw: bytes = None) -> None:
        if raw is None:
            raw = []
        self.ptrsize = ptrsize
        self.field_size = functabFieldSize
        self.raw = raw

    @property
    def size(self) -> int:
        return self.field_size * 2

    @property
    def entry(self) -> int:
        return self.value_to_uintptr(self.raw[:self.field_size])

    @property
    def funcOff(self) -> int:
        return self.value_to_uintptr(self.raw[self.field_size:])

    def value_to_uintptr(self, value: bytes) -> int:
        if self.ptrsize == 8:
            return struct.unpack("Q", value)[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", value)[0]


@dataclass(repr=False)
class FuncEntry:

    raw: bytes
    ptrsize: int
    textStart: int = 0

    nameOffset: int = 0
    resolvedName: str = ''

    args: int = 0
    frame: int = 0
    pcsp: int = 0
    pcfile: int = 0
    pcln: int = 0
    nfuncdata: int = 0
    npcdata: int = 0

    version: GoVersion = GoVersion.ver118

    def __init__(self, raw: bytes, ptrsize: int, textStart: int = 0, version: GoVersion = GoVersion.ver118):
        self.raw = raw        
        self.ptrsize = ptrsize
        self.version = version
        self.textStart = textStart
        self.__init_from_raw()

    def __init_from_raw(self):
        fields = ["nameOffset", "args", "frame", "pcsp", "pcfile", "pcln", "nfuncdata", "npcdata"]

        for idx, field in enumerate(fields, 1):
            value = self.field(idx)
            setattr(self, field, value)

    @property
    def entry(self) -> int:
        """
        func (f *funcData) entryPC() uint64 {
        // In Go 1.18, the first field of _func changed
        // from a uintptr entry PC to a uint32 entry offset.
        if f.t.version >= ver118 {
            return uint64(f.t.binary.Uint32(f.data)) + f.t.textStart
        }
        return f.t.uintptr(f.data)
        }
        """
        if self.version >= GoVersion.ver118:
            data = self.raw[:4]
            return struct.unpack("I", data)[0] + self.textStart

        data = self.raw[:self.ptrsize]
        if self.ptrsize == 8:
            return struct.unpack("Q", data)[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", data)[0]        
    
    def field(self, idx: int) -> int:
        """
        func (f funcData) field(n uint32) uint32 {
            if n == 0 || n > 9 {
                panic("bad funcdata field")
            }
            // In Go 1.18, the first field of _func changed
            // from a uintptr entry PC to a uint32 entry offset.
            sz0 := f.t.ptrsize
            if f.t.version >= ver118 {
                sz0 = 4
            }
            off := sz0 + (n-1)*4 // subsequent fields are 4 bytes each
            data := f.data[off:]
            return f.t.binary.Uint32(data)
        }
        """
        entry_field_size = self.ptrsize
        if self.version >= GoVersion.ver118:
            entry_field_size = 4

        offset_in_data = entry_field_size + (idx - 1) * 4
        data = self.raw[offset_in_data:offset_in_data + 4]
        return struct.unpack("I", data)[0]

    def __repr__(self):
        excluded = ['raw']
        excluded_types = [bytes]

        nodef_f_vals = []

        for field in dataclasses.fields(self):
            if field.name in excluded:
                continue
            atg = attrgetter(field.name)
            val = None
            try:
                val = atg(self)
                if type(val) in excluded_types:
                    continue
            except AttributeError:
                pass
            nodef_f_vals.append((
                    field.name,
                    val
                ))

        nodef_f_vals.append((
            "functionEntry",
            hex(self.entry),
        ))

        nodef_f_repr = ", ".join(f"{name}={value}" for name, value in nodef_f_vals)
        return f"{self.__class__.__name__}({nodef_f_repr})"


@dataclass(repr=False)
class GoPclnTab:
    start: int
    end: int
    raw: bytes

    quantum: int  # instruction size
    ptrsize: int  # pointer size

    valid_ptr_sizes: list

    version: GoVersion = GoVersion.ver118

    textStart: int = 0

    funcnametab: bytes = bytes()
    cutab: bytes = bytes()
    funcdata: bytes = bytes()
    functab: bytes = bytes()
    nfunctab: int = 0
    filetab: bytes = bytes()
    pctab: bytes = bytes()

    nfiletab: int = 0

    # Ignore maps which are use for caching

    def __init__(self, start, end, raw):
        self.start = start
        self.end = end
        self.raw = raw
        self.version = GoVersion.from_magic(raw[:6])
        self.valid_ptr_sizes = [4, 8]

    def functabFieldSize(self) -> int:
        if self.version >= GoVersion.ver118:
            return 4
        return self.ptrsize

    def get_byte_at(self, offset: int) -> int:
        return self.raw[offset]

    def offset(self, word: int) -> int:
        off = 8 + word * self.ptrsize
        data = self.raw[off:off+self.ptrsize]

        if self.ptrsize == 8:
            return struct.unpack("Q", data)[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", data)[0]

    def data(self, word: int) -> bytes:
        return self.raw[self.offset(word):]

    def data_after_offset(self, offset: int) -> bytes:
        return self.raw[offset:]

    def range(self, start: int, end: int) -> bytes:
        ostart = self.offset(start)
        oend = self.offset(end)
        return self.raw[ostart:oend]

    def uintptr(self, offset: int) -> int:
        value = self.raw[offset:offset+self.ptrsize]
        return self.value_to_uintptr(value)

    def value_to_uintptr(self, value: bytes) -> int:
        if self.ptrsize == 8:
            return struct.unpack("Q", value)[0]
        elif self.ptrsize == 4:
            return struct.unpack("I", value)[0]

    def uint(self, raw: bytes) -> int:
        """
        func (f funcTab) uint(b []byte) uint64 {
            if f.sz == 4 {
                return uint64(f.binary.Uint32(b))
            }
            return f.binary.Uint64(b)
        }
        """
        if self.functabFieldSize() == 4:
            data = raw[:4]
            return struct.unpack("I", data)[0]
        data = raw[:8]
        return struct.unpack("Q", data)[0]

    def funcOff(self, idx: int) -> int:
        """
        func (f funcTab) funcOff(i int) uint64 {
            return f.uint(f.functab[(2*i+1)*f.sz:])
        }
        """
        sz = self.functabFieldSize()
        start_idx = sz * (2 * idx + 1)
        end_idx = start_idx + sz
        return self.uint(self.functab[start_idx:end_idx])

    def funcAt(self, idx: int) -> FuncEntry:
        """
        func (t *LineTable) funcData(i uint32) funcData {
            data := t.funcdata[t.funcTab().funcOff(int(i)):]
            return funcData{t: t, data: data}
        }
        """

        function_start_offset = self.funcOff(idx)
        """
        sizeof(funcdata_x):
            go >= 18 -> 10 * sizeof(uint32)
            go < 18 -> ptrsize + 9 * sizeof(uint32)

        the structure has only 9 fields documented but the index can go from 0 to 9

        consider worst case:
        ptrsize = 8
        sizeof(uint32) = 4
        """

        function_data_size = 8 + 9 * 4
        function_end_offset = function_start_offset + function_data_size
        data = self.funcdata[function_start_offset:function_end_offset]
        
        function_entry = FuncEntry(data, self.ptrsize, self.textStart, self.version)
        return function_entry

    def go12FuncAt(self, idx: int) -> FuncEntry:
        line_table_entry = LineTableEntry(self.ptrsize, self.functabFieldSize())
        ostart = line_table_entry.size * idx
        oend = ostart + line_table_entry.size
        line_table_entry.raw = self.functab[ostart:oend]

        function_start_offset = line_table_entry.funcOff
        function_data_size = 8 + 9 * 4
        function_end_offset = function_start_offset + function_data_size
        data = self.funcdata[function_start_offset:function_end_offset]
        function_entry = FuncEntry(data, self.ptrsize, self.textStart, self.version)
        return function_entry

    def funcName(self, offset: int) -> str:
        """
        func (t *LineTable) funcName(off uint32) string {
        if s, ok := t.funcNames[off]; ok {
            return s
        }
        i := bytes.IndexByte(t.funcnametab[off:], 0) -> search for the 0 terminator
        s := string(t.funcnametab[off : off+uint32(i)])
        t.funcNames[off] = s
            return s
        }
        """
        # search for the terminator '\00'
        end = self.funcnametab.find(0, offset)
        name_bytes = self.funcnametab[offset:end]

        return name_bytes.decode('utf-8')

    def funcInfo(self, idx: int) -> FuncEntry:
        function = self.funcAt(idx)
        function.resolvedName = self.funcName(function.nameOffset)
        return function

    def go12FuncInfo(self, idx: int) -> FuncEntry:
        function = self.go12FuncAt(idx)
        function.resolvedName = self.funcName(function.nameOffset)
        return function
               
    def __repr__(self):
        excluded = ['raw']
        excluded_types = [bytes]

        nodef_f_vals = []

        for field in dataclasses.fields(self):
            if field.name in excluded:
                continue
            atg = attrgetter(field.name)
            val = None
            try:
                val = atg(self)
                if type(val) in excluded_types:
                    continue
            except AttributeError:
                pass
            nodef_f_vals.append((
                    field.name,
                    val
                ))

        nodef_f_repr = ", ".join(f"{name}={value}" for name, value in nodef_f_vals)
        return f"{self.__class__.__name__}({nodef_f_repr})"


def santize_gofunc_name(name):
    name = name.replace(" ", "")
    return name


class GoHelper(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv: bn.BinaryView):
        super().__init__(NAME, True)
        self.bv = bv
        self.br = bn.binaryview.BinaryReader(bv)
        self.gopclntab = None

    def init_gopclntab(self):

        gopclntab = self.get_section_by_name(".gopclntab")

        if gopclntab:
            start_addr = gopclntab.start
            end_addr = gopclntab.end
        else:
            for go_magic in [go12magic, go116magic, go118magic, go120magic]:
                start_addr = self.bv.find_next_data(0, go_magic)
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
            self.gopclntab.functab = self.gopclntab.data_after_offset(8+self.gopclntab.ptrsize)
            self.gopclntab.functabsize = (self.gopclntab.nfunctab * 2 + 1) * functabFieldSize
            self.gopclntab.functab = self.gopclntab.functab[:self.gopclntab.functabsize]
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

    def run(self):
        return self.rename_functions()


def rename_functions(bv):
    helper = FunctionRenamer(bv)
    return helper.start()
