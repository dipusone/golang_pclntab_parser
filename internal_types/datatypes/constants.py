from enum import IntEnum
from typing import List

# taken from https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go
class GoMagics:
    go12magic = b"\xfb\xff\xff\xff\x00\x00"
    go116magic = b"\xfa\xff\xff\xff\x00\x00"
    go118magic = b"\xf0\xff\xff\xff\x00\x00"
    go120magic = b"\xf1\xff\xff\xff\x00\x00"

    @classmethod
    def all(cls) -> List[bytes]:
        return [cls.go12magic, cls.go116magic, cls.go118magic, cls.go120magic]


class GoVersion(IntEnum):
    invalid = -1
    ver12 = 12
    ver116 = 116
    ver118 = 118
    ver120 = 120

    @classmethod
    def from_magic(cls, magic: bytes):
        assert len(magic) == 6
        match magic:
            case GoMagics.go12magic:
                return cls.ver12
            case GoMagics.go116magic:
                return cls.ver116
            case GoMagics.go118magic:
                return cls.ver118
            case GoMagics.go120magic:
                return cls.ver120
            case _:
                return cls.invalid

    @classmethod
    def from_string(cls, version: str):
        tokens = list(map(int, version.split(".")))
        int_version = tokens[0] * 100 + tokens[1]
        if int_version not in (cls.ver12, cls.ver116, cls.ver118, cls.ver120):
            return cls.invalid
        return int_version

    @classmethod
    def to_magic(cls, version: int):
        match version:
            case cls.ver12:
                return GoMagics.go12magic
            case cls.ver116:
                return GoMagics.go116magic
            case cls.ver118:
                return GoMagics.go118magic
            case cls.ver120:
                return GoMagics.go120magic
            case _:
                return None

    @classmethod
    def latest(cls):
        return cls.ver120


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

    @classmethod
    def _missing_(cls, value):
        return cls.INVALID

    @classmethod
    def base_type(cls, kind: int) -> bool:
        return cls.BOOL.value <= kind <= cls.COMPLEX128

    @classmethod
    def unmask(cls, kind: IntEnum) -> IntEnum:
        """
        Remove the mask from the type (e.g., interface mask)
        :param kind: the masked kind
        :return: the native kind
        """
        return cls(kind.value & 0b11111)
