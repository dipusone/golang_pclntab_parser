import struct
from abc import ABC

from enum import IntEnum
from typing import List, Optional

import binaryninja as bn

from .constants import GoVersion, GolangTypeKind


class GolangBaseType(ABC):

    version: GoVersion = GoVersion.ver118
    address: int = 0x0
    _fields: list[tuple[str, Optional[int]]] = None
    bv: bn.BinaryView = None

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        self.bv = bv
        self.address = address
        self.rodata_start = rodata_start
        self.version = version
        self.ptr_size = ptr_size or bv.arch.address_size
        if autonit:
            self._init_from_raw()

    def field_from_bv(self, bv: bn.BinaryView, size=4, offset=0) -> int:
        if not self.address:
            raise ValueError("Address must be set!")
        data = bv.read(self.address + offset, size)
        return self.decode(size, data)

    def field(self, size=4, offset=0) -> int:
        return self.field_from_bv(self.bv, size, offset)

    @staticmethod
    def decode(size, data) -> int:
        if size == 1:
            return data[0]
        if size == 2:
            return struct.unpack("H", data)[0]
        if size == 4:
            return struct.unpack("I", data)[0]
        if size == 8:
            return struct.unpack("Q", data)[0]
        raise ValueError(f"Invalid size value of {size}")

    def __repr__(self):
        excluded = []
        excluded_types = [bytes]

        nodef_f_vals = []

        for field, value in vars(self).items():
            if field in excluded:
                continue
            if type(value) in excluded_types:
                continue
            nodef_f_vals.append((
                field,
                value
            ))
        nodef_f_repr = ", ".join(f"{name}={value}" for name, value in nodef_f_vals)
        return f"{self.__class__.__name__}({nodef_f_repr})"

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

    def _init_from_raw(self):
        if self._fields:
            offset = 0
            for field, size in self._fields:
                if callable(size):
                    size = size()
                if size is None or size == '*':
                    size = self.ptr_size
                value = self.field(size, offset)
                setattr(self, field, value)
                offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        # OPT refactor to return the size read?
        ...

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        ...


class MethodType(GolangBaseType):
    name: int = 0
    mtype: int = -1
    ifn: int = -1
    tfn: int = -1

    _fields = (
        ('name', 4),
        ('mtype', 4),
        ('ifn', 4),
        ('tfn', 4),
    )

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        method = cls(bv, address)
        return method

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return sum(map(lambda field: field[1], cls._fields))


class IMethodType(GolangBaseType):
    name: int = 0
    typ: int = -1

    _fields = (
        ('name', 4),
        ('typ', 4),
    )

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        method = cls(bv, address, rodata_start=rodata_addr)
        return method

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return sum(map(lambda field: field[1], cls._fields))

    @property
    def resolved_typ(self) -> int:
        return self.rodata_start + self.typ

    @property
    def typ_address(self) -> int:
        return self.address + 0x4


class UncommonType(GolangBaseType):
    pkg_path: int = 0
    mcount: int = 0
    xcount: int = 0
    moff: int = 0
    unused: int = 0

    _fields = [
        ('pkg_path', 4),
        ('mcount', 2),
        ('xcount', 2),
        ('moff', 4),
        ('unused', 4)
    ]

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        return cls(bv, address)

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return sum(map(lambda field: field[1], cls._fields))

    @property
    def resolved_m_offset(self):
        if self.address == 0:
            raise ValueError("Base address not set")
        return self.address + self.moff

    @property
    def has_methods(self):
        return self.mcount > 0


class SliceType(GolangBaseType):
    data_ptr: int = 0
    len: int = 0
    cap: int = 0

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, False)

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        ptr_size = bv.arch.address_size
        slice_t = cls(bv, address)
        offset = 0
        slice_t.data_ptr = slice_t.field(ptr_size, offset)
        offset += ptr_size
        slice_t.len = slice_t.field(ptr_size, offset)
        offset += ptr_size
        slice_t.cap = slice_t.field(ptr_size, offset)
        return slice_t

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return bv.arch.address_size * 3


class StringType(GolangBaseType):
    data_ptr: int
    size: int

    def _init_from_raw(self):
        self.data_ptr = self.field(self.ptr_size)
        self.size = self.field(self.ptr_size, self.ptr_size)

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        string = cls(bv, address, rodata_addr, version)
        return string

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        return bv.arch.address_size * 2


# https://github.com/golang/go/blob/2c358ffe9762ba08c8db0196942395f97775e31b/src/internal/reflectlite/type.go#L151
class GolangType(GolangBaseType):

    rodata_start: int

    size: int = 0
    ptrdata: int = 0
    hash: int = 0
    tflag: int = 0
    align: int = 0
    fieldalign: int = 0
    kind: GolangTypeKind = GolangTypeKind.INVALID
    equal_fn: int = 0
    gcData: int = 0
    nameOff: int = 0
    typeOff: int = 0
    unknown: int = 0

    direct_iface: bool = False
    gc_prog: bool = False
    no_pointers: bool = False

    ptr_size: int = 0x8

    uncommon_type: UncommonType = None
    uncommon_methods: List[MethodType] = []

    # FIXME This breaks in specific circumstances
    #   For example when you open at the same time a 32bit and a 64 bit app
    _fields = None

    kind_mask: int = (1 << 5) - 1
    direct_iface_mask: int = 1 << 5
    gc_prog_mask: int = 1 << 6
    no_pointers_mask: int = 1 << 7

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        self._init_fields(bv, version)
        self.address = address
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)

    @classmethod
    def _init_fields(cls, bv: bn.BinaryView, version: GoVersion):
        cls._fields = [
            ('size', None),
            ('ptrdata', None),
            ('hash', 4),
            ('tflag', 1),
            ('align', 1),
            ('fieldalign', 1),
            ('kind', 1),
            ('equal_fn', None),
            ('gcData', None),
            ('nameOff', 4),
            ('typeOff', 4)
        ]
        if version == GoVersion.ver12:
            # Go version 12 has a different order of fields and an additional field
            cls._fields = [
                ('size', None),
                ('hash', 4),
                ('tflag', 1),
                ('align', 1),
                ('fieldalign', 1),
                ('kind', 1),
                ('equal_fn', None),
                ('gcData', None),
                ('nameOff', 4),
                ('typeOff', 4),
                ('ptrdata', None)
            ]
        fixed_fields = []
        for (field, size) in cls._fields:
            size = size or bv.arch.address_size
            fixed_fields.append((field, size))
        cls._fields = fixed_fields

    def _init_from_raw(self):
        offset = 0
        for field, size in self._fields:
            value = self.field(size, offset)
            if field == 'kind':
                self.direct_iface = value & self.direct_iface_mask != 0
                self.gc_prog = value & self.gc_prog_mask != 0
                self.no_pointers = value & self.no_pointers_mask != 0
                value = GolangTypeKind(value & self.kind_mask)
            setattr(self, field, value)
            offset += size

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        golang_type = cls(bv, address, rodata_addr, version)
        golang_type.address = address
        return golang_type

    def add_uncommon_type(self, bv, address):
        if not self.has_uncommon:
            return 0
        self.uncommon_type = UncommonType.from_bv(bv, address)
        self.uncommon_type.address = address
        return UncommonType.size_from_bv(bv, address)

    def add_uncommon_methods(self, bv):
        if not (self.has_uncommon and self.uncommon_type.has_methods):
            return
        methods_address = self.uncommon_type.resolved_m_offset
        self.uncommon_methods = []
        offset = 0
        for _ in range(self.uncommon_type.mcount):
            self.uncommon_methods.append(MethodType.from_bv(bv, methods_address + offset))
            offset += MethodType.size_from_bv(bv)
        return offset

    def add_ptrdata_go12_field(self, offset: int):
        if self.version is GoVersion.ver12:
            self.unknown = self.field(self.ptr_size, offset)
            offset += self.ptr_size
        return offset

    @property
    def resolved_name_addr(self) -> int:
        if self.version == GoVersion.ver12:
            return self.nameOff
        return self.rodata_start + self.nameOff

    @property
    def resolved_type_off(self) -> int:
        return self.rodata_start + self.typeOff

    def address_off(self, field: str) -> int:
        offset = 0
        for name, size in self._fields:
            if field == name:
                return self.address + offset
            offset += size

    def align_offset(self, address: int, offset: int) -> int:
        if self.fieldalign:
            missalign = (address + offset) % self.fieldalign
            if missalign:
                offset += self.fieldalign - missalign
        return offset

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        cls._init_fields(bv, version)
        return sum(map(lambda field: field[1], cls._fields))

    @property
    def has_uncommon(self):
        return self.tflag & 0x1 == 1

    @property
    def extra_star(self):
        return self.tflag & (0x1 < 1) == 1

    @property
    def named(self):
        return self.tflag & (0x1 < 2) == 1

    @property
    def regular_memory(self):
        return self.tflag & (0x1 < 3) == 1

    def is_valid(self, rodata: bn.Section) -> bool:
        if self.kind is GolangTypeKind.INVALID:
            return False
        if self.gcData not in rodata:
            return False
        return True


class TypeName(GolangBaseType):
    bitfield: int
    size: int
    name: str

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)
        self.bitfield = self.field(1, 0)

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        if version > GoVersion.ver116:
            # Skip the bitfield and read the correct size from varint
            string_len, read = cls.read_varint(bv, address + 0x1)
            offset_from_start = 0x1 + read
        else:
            string_len = struct.unpack("B", bv.read(address + 0x2, 1))[0]
            offset_from_start = 0x3
        name_addr = address + offset_from_start

        # Future self note: this method is here for convenience in parameters declaration
        if version == GoVersion.ver12:
            # https://github.com/golang/go/blob/release-branch.go1.12/src/runtime/type.go#L28
            string = StringType.from_bv(bv, address, rodata_addr, version)
            name_addr = string.data_ptr
            string_len = string.size

        name = bv.read(name_addr, string_len).decode('utf-8')
        if not name or len(name) == 0:
            name = ""

        type_name = cls(bv, address, rodata_addr, version)
        type_name.size = string_len
        type_name.name = name
        return type_name


class StructField(GolangBaseType):
    name_ptr: int = 0
    type_ptr: int = 0
    offset: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):
        ptr_size = bv.arch.address_size
        struct_field = cls(bv, address)
        if version == GoVersion.ver12:
            offset = 0
            struct_field.name_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            # skip unk field
            offset += ptr_size
            struct_field.type_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            # skip unk field
            offset += ptr_size
            struct_field.offset = struct_field.field(ptr_size, offset)
        else:
            offset = 0
            struct_field.name_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            struct_field.type_ptr = struct_field.field(ptr_size, offset)
            offset += ptr_size
            struct_field.offset = struct_field.field(ptr_size, offset)
        return struct_field

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        if version == GoVersion.ver12:
            return bv.arch.address_size * 5
        return bv.arch.address_size * 3


class InterfaceType(GolangType):
    """
    type interfaceType struct {
	    rtype
	    pkgPath name      // import path -> it is a ptr?
	    methods []imethod // sorted by hash
    }
    """
    pkgPath: int = 0
    methods: SliceType = None
    methods_array: List[IMethodType] = None

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)
        self.methods = SliceType(bv, address, autonit=False)
        self.methods_array = []

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):

        interface_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        offset = super().size_from_bv(bv, version)
        interface_type.pkgPath = interface_type.field(bv.arch.address_size, offset)
        offset += bv.arch.address_size

        interface_type.methods = SliceType.from_bv(bv, address + offset, rodata_addr, version)
        offset += SliceType.size_from_bv(bv, address + offset)
        offset += interface_type.add_uncommon_type(bv, address + offset)

        array_instances_offset = 0
        methods_address = interface_type.methods.data_ptr

        for _ in range(interface_type.methods.len):
            interface_type.methods_array.append(
                IMethodType.from_bv(bv,
                                    methods_address + array_instances_offset,
                                    rodata_addr,
                                    version
                                    )
            )
            array_instances_offset += IMethodType.size_from_bv(bv, version)
            offset = interface_type.align_offset(methods_address, offset)

        interface_type.add_uncommon_methods(bv)
        return interface_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        raise NotImplementedError()


class StructType(GolangType):
    pkgPath: int = 0
    fields: SliceType = None
    uncommon_type: UncommonType = None
    fields_list: List[StructField] = None
    uncommon_methods: List[MethodType] = []

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):

        struct_type = cls(bv, address, rodata_addr, version)
        struct_type.address = address
        offset = super().size_from_bv(bv, version)
        struct_type.pkgPath = struct_type.field(struct_type.ptr_size, offset)
        offset += struct_type.ptr_size
        struct_type.fields = SliceType.from_bv(bv, address + offset, rodata_addr, version)
        offset += SliceType.size_from_bv(bv)
        offset += struct_type.add_uncommon_type(bv, address + offset)
        if not struct_type.fields_list:
            struct_type.fields_list = []
        offset = 0
        fields_address = struct_type.fields.data_ptr
        for _ in range(struct_type.fields.len):
            struct_type.fields_list.append(
                StructField.from_bv(bv,
                                    fields_address + offset,
                                    rodata_addr,
                                    version))
            offset += StructField.size_from_bv(bv, version)
            # align  the fields
            offset = struct_type.align_offset(address, offset)

        struct_type.add_uncommon_methods(bv)
        return struct_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        # A structure size is dependant from its fields
        if not address:
            raise ValueError("address required")
        tmp_struct = cls.from_bv(bv, address, 0x0)
        struct_type_size = super().size_from_bv(bv, address) + bv.arch.address_size * 4
        if tmp_struct.has_uncommon:
            struct_type_size += UncommonType.size_from_bv(bv)
        struct_type_size += tmp_struct.fields.len * StructField.size_from_bv(bv)
        # this is an approximation since there might be some fields which are not alligned
        return struct_type_size


class ArrayType(GolangType):
    element_ptr: int = 0
    slice_ptr: int = 0
    len: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):
        array_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        array_type.address = address
        offset = super().size_from_bv(bv, version)
        offset = array_type.add_ptrdata_go12_field(offset)
        array_type.element_ptr = array_type.field(array_type.ptr_size, offset)
        offset += array_type.ptr_size
        array_type.slice_ptr = array_type.field(array_type.ptr_size, offset)
        offset += array_type.ptr_size
        array_type.len = array_type.field(array_type.ptr_size, offset)
        offset += array_type.ptr_size
        offset += array_type.add_uncommon_type(bv, address + offset)
        array_type.add_uncommon_methods(bv)
        return array_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        array_size = super().size_from_bv(bv, address) + bv.arch.address_size * 3
        return array_size


class ChanDirection(IntEnum):
    recv_only = 0x0
    send_only = 0x1
    send_receive = 0x2


class ChanDirectionType(IntEnum):
    recv_only = 0x1
    send_only = 0x2
    send_receive = 0x3


class ChanType(GolangType):
    element_ptr: int = 0
    direction: ChanDirectionType = ChanDirectionType.recv_only

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        chan_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        chan_type.address = address
        offset = super().size_from_bv(bv, version)
        offset = chan_type.add_ptrdata_go12_field(offset)
        chan_type.element_ptr = chan_type.field(chan_type.ptr_size, offset)
        offset += chan_type.ptr_size
        direction = chan_type.field(chan_type.ptr_size, offset)
        chan_type.direction = ChanDirectionType(direction)
        offset += chan_type.ptr_size
        chan_type.add_uncommon_type(bv, address + offset)
        chan_type.add_uncommon_methods(bv)
        return chan_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        chan_size = super().size_from_bv(bv, address) + bv.arch.address_size * 2
        return chan_size


class SliceTType(GolangType):
    element_ptr: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        slice_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        slice_type.address = address
        offset = super().size_from_bv(bv, version)
        offset = slice_type.add_ptrdata_go12_field(offset)
        slice_type.element_ptr = slice_type.field(slice_type.ptr_size, offset)
        offset += slice_type.ptr_size
        offset += slice_type.add_uncommon_type(bv, address + offset)
        slice_type.add_uncommon_methods(bv)
        return slice_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        chan_size = super().size_from_bv(bv, address) + bv.arch.address_size * 2
        return chan_size


class PtrType(GolangType):
    element_ptr: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):
        ptr_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        ptr_type.address = address
        offset = super().size_from_bv(bv, version)
        offset = ptr_type.add_ptrdata_go12_field(offset)
        ptr_type.element_ptr = ptr_type.field(ptr_type.ptr_size, offset)
        offset += ptr_type.ptr_size
        offset += ptr_type.add_uncommon_type(bv, address + offset)
        ptr_type.add_uncommon_methods(bv)
        return ptr_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        ptr_type = super().size_from_bv(bv, address) + bv.arch.address_size
        return ptr_type


class UnsafePtrType(PtrType):
    pkg_path: int = 0

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        ptr_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        ptr_type.address = address
        offset = super().size_from_bv(bv, version)
        offset = ptr_type.add_ptrdata_go12_field(offset)
        ptr_type.pkg_path = ptr_type.field(ptr_type.ptr_size, offset)
        offset += ptr_type.ptr_size
        offset += ptr_type.add_uncommon_type(bv, address + offset)
        ptr_type.add_uncommon_methods(bv)
        return ptr_type


class FuncType(GolangType):
    """
    type funcType struct {
	    rtype
	    inCount  uint16
	    outCount uint16 // top bit is set if last input parameter is ...
    }
    a function type with one method, one input, and one output is:
     struct {
        funcType
        uncommonType
        [2]*rtype  // [0] is in, [1] is out
    }
    """

    in_count: int = 0
    out_count: int = 0
    in_params: list[int] = None
    out_params: list[int] = None
    variadic: bool = False

    def __init__(self, bv: bn.BinaryView, address: int, rodata_start: int = 0,
                 version: GoVersion = GoVersion.ver118, ptr_size: int = None, autonit: bool = True):
        super().__init__(bv, address, rodata_start, version, ptr_size, autonit)
        self.in_params = []
        self.out_params = []

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0, version: GoVersion = GoVersion.ver118):

        func_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)

        func_type.address = address

        offset = super().size_from_bv(bv, version)
        offset = func_type.add_ptrdata_go12_field(offset)
        func_type.in_count = func_type.field(2, offset)
        offset += 2
        func_type.out_count = func_type.field(2, offset)
        offset += 2

        # Top bit is set if out last param is '...'
        if func_type.out_count & (1 << 15):
            func_type.out_count = (func_type.out_count & 0x7fff)
            func_type.variadic = True

        offset += func_type.add_uncommon_type(bv, address + offset)

        offset = func_type.align_offset(address, offset)

        for _ in range(func_type.in_count):
            func_type.in_params.append(func_type.field(
                func_type.ptr_size,
                offset))
            offset += bv.arch.address_size

        for _ in range(func_type.out_count):
            func_type.out_params.append(func_type.field(
                func_type.ptr_size,
                offset))
            offset += bv.arch.address_size

        func_type.add_uncommon_methods(bv)
        return func_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        func_type = super().size_from_bv(bv, address) + 2 + 2
        return func_type


class MapType(GolangType):
    key: int = 0
    elem: int = 0
    bucket: int = 0
    hasher: int = 0
    keysize: int = 0
    valuesize: int = 0
    bucketsize: int = 0
    flags: int = 0

    _additional_fields = (
        ('key', None),
        ('elem', None),
        ('bucket', None),
        ('hasher', None),
        ('keysize', 1),
        ('valuesize', 1),
        ('bucketsize', 2),
        ('flags', 4)
    )

    @classmethod
    def from_bv(cls, bv: bn.BinaryView, address: int, rodata_addr: int = 0,
                version: GoVersion = GoVersion.ver118):

        map_type = cls(bv, address, rodata_addr, version, bv.arch.address_size)
        map_type.address = address

        offset = super().size_from_bv(bv, version)
        offset = map_type.add_ptrdata_go12_field(offset)
        for field, size in map_type._additional_fields:
            if not size:
                size = map_type.ptr_size
            value = map_type.field(size, offset)
            setattr(map_type, field, value)
            offset += size
        offset += map_type.add_uncommon_type(bv, address + offset)
        map_type.add_uncommon_methods(bv)
        return map_type

    @classmethod
    def size_from_bv(cls, bv: bn.BinaryView, address: int = None, version: GoVersion = GoVersion.latest()):
        base_size = super().size_from_bv(bv, address)
        additional_space = 0
        for _, size in cls._additional_fields:
            if not size:
                size = bv.arch.address_size
            additional_space += size
        return base_size + additional_space
