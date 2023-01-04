import dataclasses
import struct

from dataclasses import dataclass
from enum import IntEnum
from operator import attrgetter

import binaryninja

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
    deferreturn: int = 0
    pcfile: int = 0
    pcln: int = 0
    nfuncdata: int = 0
    cuOffset: int = 0

    version: GoVersion = GoVersion.ver118

    def __init__(self, raw: bytes, ptrsize: int, textStart: int = 0, version: GoVersion = GoVersion.ver118):
        self.raw = raw
        self.ptrsize = ptrsize
        self.version = version
        self.textStart = textStart
        self.__init_from_raw()

    def __init_from_raw(self):
        fields = ["nameOffset", "args", "frame", "deferreturn", "pcfile", "pcln", "nfuncdata", "cuOffset"]

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
        data = self.raw[off:off + self.ptrsize]

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
        value = self.raw[offset:offset + self.ptrsize]
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

    def fileName(self, idx) -> bytes:
        if self.version == GoVersion.ver12:
            start = 4 * (idx + 1)
            offset = struct.unpack("I", self.filetab[start:start + 4])[0]
            string_end = self.funcdata.find(0, offset)
            string = self.funcdata[offset:string_end]
            return string
        else:
            offset = 0
            for i in range(idx + 1):
                string_end = self.filetab.find(0, offset)
                string = self.filetab[offset:string_end]
                if i == idx:
                    return string
                offset += len(string) + 1
        return b""

    def pc2filename(self, function: FuncEntry) -> bytes:
        """
        func (t *LineTable) go12PCToFile(pc uint64) (file string) {
            entry := f.entryPC()
            filetab := f.pcfile()
            fno := t.pcvalue(filetab, entry, pc)
            if t.version == ver12 {
                if fno <= 0 {
                    return ""
                }
                return t.string(t.binary.Uint32(t.filetab[4*fno:]))
            }
            // Go ≥ 1.16
            if fno < 0 { // 0 is valid for ≥ 1.16
                return ""
            }
            cuoff := f.cuOffset()
            if fnoff := t.binary.Uint32(t.cutab[(cuoff+uint32(fno))*4:]); fnoff != ^uint32(0) {
                return t.stringFrom(t.filetab, fnoff)
            }
            return ""
        }
        """
        entry = function.entry
        filetab = function.pcfile
        targetpc = function.entry
        offset = self.pcvalue(filetab, entry, targetpc)

        if self.version == GoVersion.ver12:
            if offset <= 0:
                return b''
            else:
                return self.fileName(offset - 1)
        if offset < 0:
            return b''

        compilation_unit_offset = function.cuOffset
        start = (compilation_unit_offset + offset) * 4
        offset = struct.unpack("I", self.cutab[start:start + 4])[0]
        if offset != self.make_mask(4):
            string_end = self.filetab.find(0, offset)
            string = self.filetab[offset:string_end]
            return string
        return b''

    def pcvalue(self, offset: int, pc: int, targetpc: int) -> int:
        """
        func (t *LineTable) pcvalue(off uint32, entry, targetpc uint64) int32 {
            p := t.pctab[off:]

            val := int32(-1)
            pc := entry
            for t.step(&p, &pc, &val, pc == entry) {
                if targetpc < pc {
                    return val
                }
            }
            return -1
        }
        """
        val = -1
        offset, pc, val, ok = self.step(self.pctab, offset, pc, val, True)
        while ok:
            if targetpc < pc:
                return val
            offset, pc, val, ok = self.step(self.pctab, offset, pc, val, False)
        return -1

    def step(self, table: bytes, offset_in_table: int, pc: int, val: int, first: bool) -> (int, int, int, bool):
        """
        // step advances to the next pc, value pair in the encoded table.
        func (t *LineTable) step(p *[]byte, pc *uint64, val *int32, first bool) bool {
            uvdelta := t.readvarint(p)
            if uvdelta == 0 && !first {
                return false
            }
            if uvdelta&1 != 0 {
                uvdelta = ^(uvdelta >> 1)
            } else {
                uvdelta >>= 1
            }
            vdelta := int32(uvdelta) -> there might be some type/sign shenanigans
            pcdelta := t.readvarint(p) * t.quantum
            *pc += uint64(pcdelta)
            *val += vdelta
            return true
        }
        """
        uvdelta, read = self.read_varint(table, offset_in_table)
        offset_in_table += read

        if uvdelta == 0 and not first:
            return 0, 0, -1, False

        if uvdelta & 1:
            mask = self.make_mask(read)
            uvdelta = ~(uvdelta >> 1) & mask
        else:
            uvdelta = uvdelta >> 1

        vdelta = uvdelta  # There might be some sign parsing/shenanigans in the original code
        pcdelta, read = self.read_varint(table, offset_in_table)
        offset_in_table += read
        pcdelta = pcdelta * self.quantum

        new_pc = pc + pcdelta
        new_val = val + vdelta
        return offset_in_table, new_pc, new_val, True

    @staticmethod
    def read_varint(raw: bytes, offset: int = 0) -> (int, int):
        shift = 0
        result = 0
        read = 0
        while True:
            i = raw[offset + read]
            result |= (i & 0x7f) << shift
            shift += 7
            read += 1
            if not (i & 0x80):
                break
        return result, read

    @staticmethod
    def make_mask(bytes_cnt: int) -> int:
        mask = 0
        for i in range(bytes_cnt):
            mask = mask << 8 | 0xff
        return mask

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


class GolangTypeKind(IntEnum):
    INVALID = 0x0
    BOOL = 0x1
    INT = 0x2
    INT8 = 0x3
    INT16 = 0x4
    INT32 = 0x5
    INT64 = 0x6
    UINT = 0x7
    UINT8 = 0x8
    UINT16 = 0x9
    UINT32 = 0xA
    UINT64 = 0xB
    UINTPTR = 0xC
    FLOAT32 = 0xD
    FLOAT64 = 0xE
    COMPLEX64 = 0xF
    COMPLEX128 = 0x10
    ARRAY = 0x11
    CHAN = 0x12
    FUNC = 0x13
    INTERFACE = 0x14
    MAP = 0x15
    PTR = 0x16
    SLICE = 0x17
    STRING = 0x18
    STRUCT = 0x19
    UNSAFEPTR = 0x1A
    CHAN_DIRECTIFACE = 0x32
    FUNC_DIRECTIFACE = 0x33
    MAP_DIRECTIFACE = 0x35
    STRUCT_DIRECTIFACE = 0x39

    @classmethod
    def _missing_(cls, value):
        return cls.INVALID


@dataclass(repr=False)
class GolangType:

    raw: bytes
    rodata_start: int

    size: int = 0
    ptrdata: int = 0
    hash: int = 0
    tflag: int = 0
    align: int = 0
    fieldaligh: int = 0
    kind: GolangTypeKind = GolangTypeKind.INVALID
    equal_fn: int = 0
    gcData: int = 0
    nameOff: int = 0
    typeOff: int = 0
    name: int = 0
    mhdr: int = 0

    SIZE: int = 0x40

    fields = [
        ('size', 8),
        ('ptrdata', 8),
        ('hash', 4),
        ('tflag', 1),
        ('align', 1),
        ('fieldalign', 1),
        ('golang_kind', 1),
        ('equal_fn', 8),
        ('gcData', 8),
        ('nameOff', 4),
        ('typeOff', 4),
        ('name', 8),
        ('mhdr', 8),
    ]

    version: GoVersion = GoVersion.ver118

    def __init__(self, raw: bytes, rodata_start: int = 0, version: GoVersion = GoVersion.ver118):
        self.raw = raw
        self.rodata_start = rodata_start
        self.version = version
        self.__init_from_raw()
        self.__addr = 0

    def __init_from_raw(self):
        offset = 0
        for field, size in self.fields:
            value = self.field(size, offset)
            if field == 'golang_kind':
                value = GolangTypeKind(value)
            setattr(self, field, value)
            offset += size

    def field(self, size=4, offset=0) -> int:
        data = self.raw[offset:offset + size]
        if size == 1:
            return data[0]
        if size == 4:
            return struct.unpack("I", data)[0]
        if size == 8:
            return struct.unpack("Q", data)[0]

    @classmethod
    def from_bv(cls, bv: binaryninja.BinaryView, address: int, rodata_addr: int, version: GoVersion = GoVersion.ver118):
        raw = bv.read(address, cls.SIZE)
        golang_type = cls(raw, rodata_addr, version)
        golang_type.__addr = address
        return golang_type

    @property
    def resolved_name_addr(self) -> int:
        return self.rodata_start + self.nameOff

    def address_off(self, field: str) -> int:
        offset = 0
        for name, size in self.fields:
            if field == name:
                return self.__addr + offset
            offset += size

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


@dataclass(repr=False)
class TypeName:

    raw: bytes

    bitfield: int
    size: int
    name: str

    version: GoVersion = GoVersion.ver118

    def __init__(self, raw: bytes, version: GoVersion = GoVersion.ver118):
        self.raw = raw
        self.bitfield = raw[0]
        self.version = version

    @classmethod
    def from_bv(cls, bv: binaryninja.BinaryView, address: int, version: GoVersion = GoVersion.ver118):
        string_len = bv.read(address + 0x1, 1)
        offset_from_start = 0x2
        if version >= GoVersion.ver116:
            # Skip the bitfield and read the correct size from varint
            string_len, read = cls.read_varint(bv, address + 0x1)
            offset_from_start = 0x1 + read
        name_addr = address + offset_from_start
        name = bv.get_ascii_string_at(name_addr,
                                      max_length=string_len,
                                      require_cstring=False)
        name = name.value
        if not name or len(name) == 0:
            name = ""

        raw = bv.read(address, offset_from_start + string_len)

        type_name = cls(raw, version)
        type_name.size = string_len
        type_name.name = name
        return type_name

    @staticmethod
    def read_varint(bv, start_addr: int) -> (int, int):
        shift = 0
        result = 0
        read = 0
        while True:
            i = bv.read(start_addr + read, 1)[0]
            result |= (i & 0x7f) << shift
            shift += 7
            read += 1
            if not (i & 0x80):
                break
        return result, read

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
