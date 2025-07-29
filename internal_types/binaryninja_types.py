import binaryninja as bn

from abc import ABC
from typing import Union, Type as Ttype, Optional

from binaryninja.types import (
    Type,
    StructureBuilder,
    IntegerType,
    TypeBuilder,
    PointerType,
    ArrayType,
    BoolType,
    FloatType,
    CharType,
    VoidType
)

from .datatypes import (
    GolangType,
    GolangTypeKind,
    GoVersion,
    ChanDirectionType,
    StructType,
    ChanDirection,
    FuncType,
    InterfaceType
)

"""
Most of the types can be extracted from
https://github.dev/golang/go/blob/release-branch.go1.12/src/runtime/type.go
https://github.dev/golang/go/blob/master/src/reflect/type.go
"""

GOLAND_TYPES = []


def register_type(cls=None):
    global GOLAND_TYPES
    if cls in GOLAND_TYPES:
        raise ValueError(f"Trying to add the same class multiple times {cls}")
    for gt in GOLAND_TYPES:
        if gt.name == cls.name:
            raise ValueError(f"Trying to add an object with the same name field: {cls} -> {gt}")
    GOLAND_TYPES.append(cls)
    return cls


class GolangTypeBuilderABC(ABC):
    # TODO make bv part of the class constructor ?
    base = 'base'
    prefix = 'golang'
    suffix = 't'
    name = f'{prefix}_{base}_{suffix}'
    signed = True

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        pass

    @classmethod
    def fmt_name(cls, type_name: str):
        return f"{cls.prefix}_{type_name}_{cls.suffix}"


def get_type_from_tb(bv: bn.BinaryView, type_class: Ttype[GolangTypeBuilderABC]) -> Union[Type, TypeBuilder]:
    return Type.named_type_from_registered_type(bv, type_class.name)


def get_type_from_base_type_name(bv: bn.BinaryView, name: str) -> Optional[Union[Type, TypeBuilder]]:
    for possible_type in GOLAND_TYPES:
        if GolangTypeBuilderABC.fmt_name(name) == possible_type.name:
            return get_type_from_tb(bv, possible_type)


_GOLANG_BASE_NATIVE_TYPES = (
    ('bool', 1, True),
    ('int', None, True),
    ('int8', 1, True),
    ('int16', 2, True),
    ('int32', 4, True),
    ('int64', 8, True),
    ('uint', None, True),
    ('uint8', 1, False),
    ('uint16', 2, False),
    ('uint32', 4, False),
    ('uint64', 8, False),
    ('uintptr', None, False),
    ('byte', 1, True),
    ('rune', 4, True),
    ('float32', 4, True),
    ('float64', 8, True),
    ('complex64', 8, True),
    ('complex128', 16, True),
)


class BaseIntTypeBuilder(GolangTypeBuilderABC):
    size = 0x0
    signed = False

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        return IntegerType.create(width=self.size, sign=self.signed)


def dynamically_build_int_types() -> list:
    new_types = []

    def build_bool(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        return BoolType.create()

    def build_int(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        size = self.size or bv.arch.address_size
        return IntegerType.create(width=size, sign=self.signed)

    def build_float(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        return FloatType.create(width=self.size)

    def build_ptr(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        return PointerType.create(bv.arch, VoidType.create())

    def get_handler(name: str):
        if name == 'bool':
            return build_bool
        elif name.startswith('float'):
            return build_float
        elif name.endswith('ptr'):
            return build_ptr
        return build_int

    for type_name, size, signed in _GOLANG_BASE_NATIVE_TYPES:
        builder_name = f"{type_name.capitalize()}TBuilder"
        tb = type(builder_name, (BaseIntTypeBuilder,), {
            'signed': signed,
            'size': size,
            'name': f"golang_{type_name}_t",
            'build_type': get_handler(type_name)
        })
        new_types.append(tb)
    return new_types


GOLAND_TYPES.extend(dynamically_build_int_types())


@register_type
class UinptrTBuilder(GolangTypeBuilderABC):
    name = 'golang_uintprt_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        return IntegerType.create(width=bv.arch.address_size)


# src/runtime/slice.go
@register_type
class SliceTBuilder(GolangTypeBuilderABC):
    name = 'golang_slice_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        ptr_size = bv.arch.address_size
        slice_t = StructureBuilder.create()
        void_ptr = PointerType.create(bv.arch, Type.void())
        slice_t.append(PointerType.create(bv.arch, void_ptr), 'Data')
        slice_t.append(IntegerType.create(width=ptr_size, sign=False), 'Len')
        slice_t.append(IntegerType.create(width=ptr_size, sign=False), 'Cap')
        return slice_t


@register_type
class UnsafePtrTBuilder(GolangTypeBuilderABC):
    name = 'golang_unsafe_ptr_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        return PointerType.create(bv.arch, Type.void())


@register_type
class IMethodTBuilder(GolangTypeBuilderABC):
    base = 'golang_imethod'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        imethod_t = StructureBuilder.create()
        imethod_t.append(IntegerType.create(4, False), 'name')
        imethod_t.append(IntegerType.create(4, False), 'typ')
        return imethod_t


@register_type
class StringTBuilder(GolangTypeBuilderABC):
    name = 'golang_string_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        ptr_size = bv.arch.address_size
        slice_t = StructureBuilder.create()
        # char_ptr = bv.parse_type_string("char")[0]
        slice_t.append(PointerType.create(bv.arch,  CharType.create()), 'Data')
        slice_t.append(IntegerType.create(width=ptr_size, sign=False), 'Len')
        return slice_t


@register_type
class MethodTypeTBuilder(GolangTypeBuilderABC):
    name = 'golang_method_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        method_t = StructureBuilder.create()
        method_t.append(IntegerType.create(width=4, sign=False), 'name')
        method_t.append(IntegerType.create(width=4, sign=False), 'mtype')
        method_t.append(IntegerType.create(width=4, sign=False), 'ifn')
        method_t.append(IntegerType.create(width=4, sign=False), 'tfn')
        return method_t


@register_type
class GolangTypeKindBuilder(GolangTypeBuilderABC):
    name = 'golang_type_kind_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        """
           The accurate structure for a kind would be:
           struct golang_bitfield {
           	bool NoPointer: 1;
           	bool GCProg: 1;
           	bool DirectIface: 1;
           	uint8_t kind: 5;
           };
           """

        kind_masks = [
            ('DIRECTIFACE', GolangType.direct_iface_mask),
            ('GCPROG', GolangType.gc_prog_mask),
            ('NOPOINTERS', GolangType.no_pointers_mask)
        ]

        types = [(etype.name, etype.value) for etype in GolangTypeKind]

        for mask_name, mask_value in kind_masks:
            masked_types = []
            for key, val in types:
                masked_val = val | mask_value
                masked_types.append((f"{key}_{mask_name}", masked_val))
            types.extend(masked_types)
        et = Type.enumeration(members=types, width=1)
        return et


@register_type
class GolangTypeBuilder(GolangTypeBuilderABC):
    base = 'golang_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder, StructureBuilder]:
        golang_type = StructureBuilder.create()
        golang_type.append(IntegerType.create(width=bv.arch.address_size), "size")
        void_ptr_t = PointerType.create(bv.arch, Type.void())
        if go_version is not GoVersion.ver12:
            golang_type.append(void_ptr_t, "ptrdata")
        golang_type.append(IntegerType.create(width=4), "hash")
        golang_type.append(IntegerType.create(width=1, sign=False), "tflag")
        golang_type.append(IntegerType.create(width=1, sign=False), "align")
        golang_type.append(IntegerType.create(width=1, sign=False), "fieldalign")
        golang_kind_t = get_type_from_tb(bv, GolangTypeKindBuilder)
        golang_type.append(golang_kind_t, 'kind')
        golang_type.append(void_ptr_t, 'equal_fn')
        golang_type.append(void_ptr_t, 'gcData')

        offset_type = IntegerType.create(width=4)
        if go_version is GoVersion.ver12:
            offset_type = PointerType.create_with_width(4, Type.void())

        golang_type.append(offset_type, 'nameoff')
        golang_type.append(offset_type, 'typeoff')
        if go_version == GoVersion.ver12:
            golang_type.append(void_ptr_t, "ptrdata")
            # Go 12 seems to have a ptr pointing to the PTR to this type
            golang_type.append(void_ptr_t, "ptr_type_ptr")
        return golang_type

    def build_type_from_gtype(self, bv, gtype: GolangType) -> tuple[Union[Type, StructureBuilder], str]:
        golang_type: StructureBuilder = self.build_type(bv, gtype.version)
        type_name = self.base
        if gtype.has_uncommon:
            uncommon_type_t = get_type_from_tb(bv, UncommonTypeBuilder)
            golang_type.append(uncommon_type_t, 'uncommon_type')
            type_name += UncommonTypeBuilder.sfx
            method_t = get_type_from_tb(bv, MethodTypeTBuilder)
            method_array = ArrayType.create(method_t, gtype.uncommon_type.mcount)
            golang_type.append(method_array, 'uncommon_methods')
        type_name += '_t'
        return golang_type, type_name


@register_type
class UncommonTypeBuilder(GolangTypeBuilderABC):
    name = 'golang_uncommon_type_t'
    sfx = '_U_'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder, StructureBuilder]:
        uncommon_type = StructureBuilder.create()
        uncommon_type.append(IntegerType.create(4), 'pkgPath')
        uncommon_type.append(IntegerType.create(2, False), 'mcount')
        uncommon_type.append(IntegerType.create(2, False), 'xcount')
        uncommon_type.append(IntegerType.create(4, False), 'moff')
        uncommon_type.append(IntegerType.create(4, False), '_')
        return uncommon_type


@register_type
class GolangStructFieldBuilder(GolangTypeBuilderABC):
    base = 'golang_struct'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        ptr_size = bv.arch.address_size
        struct_field = StructureBuilder.create()
        struct_field.append(IntegerType.create(width=ptr_size), "name")

        golang_kind_t = get_type_from_tb(bv, GolangTypeKindBuilder)

        if go_version == GoVersion.ver12:
            struct_field.append(IntegerType.create(ptr_size, False), '_')
            struct_field.append(PointerType.create(bv.arch, golang_kind_t), 'typ')
            struct_field.append(IntegerType.create(ptr_size, False), '__')
        else:
            struct_field.append(PointerType.create(bv.arch, golang_kind_t), 'typ')

        struct_field.append(IntegerType.create(ptr_size, False), 'offset')

        return struct_field


@register_type
class GolangStructTypeBuilder(GolangTypeBuilder):
    base = 'golang_struct_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder, StructureBuilder]:
        bt = super().build_type(bv, go_version)
        struct_type: StructureBuilder = bt.mutable_copy()
        if go_version is not GoVersion.ver12:
            struct_type.append(IntegerType.create(width=bv.arch.address_size), "pkgPath")
        fields_slice = get_type_from_tb(bv, SliceTBuilder)
        struct_type.append(fields_slice, 'fields')
        return bt

    def build_type_from_gtype(self, bv, gtype: StructType) -> tuple[Union[Type, StructureBuilder], str]:
        struct_type: StructureBuilder = self.build_type(bv, gtype.version)
        type_name = f"golang_struct_type"
        if gtype.has_uncommon:
            uncommon_type_t = get_type_from_tb(bv, UncommonTypeBuilder)
            struct_type.append(uncommon_type_t, 'uncommon_type')
            type_name += UncommonTypeBuilder.sfx
        struct_field_t = get_type_from_tb(bv, GolangStructFieldBuilder)
        if gtype.fields.len:
            struct_type.append(ArrayType.create(struct_field_t, gtype.fields.len), 'struct_fields')
            type_name += f"[{gtype.fields.len}]"
        if gtype.has_uncommon:
            method_t = get_type_from_tb(bv, MethodTypeTBuilder)
            method_array = ArrayType.create(method_t, gtype.uncommon_type.mcount)
            struct_type.append(method_array, 'uncommon_methods')
        type_name += '_t'
        return struct_type, type_name


@register_type
class InterfaceTypeTBuilder(GolangTypeBuilder):
    base = 'golang_interface_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[
        bn.Type, TypeBuilder, StructureBuilder]:
        bt = super().build_type(bv, go_version)
        interface_type: StructureBuilder = bt.mutable_copy()
        if go_version is not GoVersion.ver12:
            interface_type.append(IntegerType.create(4), 'pkgPath')
        slice_t = get_type_from_tb(bv, SliceTBuilder)
        interface_type.append(slice_t, 'methods')
        return bt

    def build_type_from_gtype(self, bv, gtype: InterfaceType) -> tuple[Union[Type, StructureBuilder], str]:
        interface_type: StructureBuilder = self.build_type(bv, gtype.version)
        type_name = self.base
        if gtype.has_uncommon:
            uncommon_type_t = get_type_from_tb(bv, UncommonTypeBuilder)
            interface_type.append(uncommon_type_t, 'uncommon_type')
            type_name += UncommonTypeBuilder.sfx

        if gtype.methods.len:
            imethod_type_t = get_type_from_tb(bv, IMethodTBuilder)
            interface_type.append(ArrayType.create(imethod_type_t, gtype.methods.len), 'imethods')
            type_name += f"[{gtype.methods.len}]"
        if gtype.has_uncommon:
            method_t = get_type_from_tb(bv, MethodTypeTBuilder)
            method_array = ArrayType.create(method_t, gtype.uncommon_type.mcount)
            interface_type.append(method_array, 'uncommon_methods')
        type_name += '_t'
        return interface_type, type_name


@register_type
class ChanDirectionTBuilder(GolangTypeBuilderABC):
    base = 'golang_chan_direction'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:

        types = [(etype.name, etype.value) for etype in ChanDirection]
        et = Type.enumeration(members=types, width=1)
        return et


@register_type
class ChanTBuilder(GolangTypeBuilderABC):
    base = 'golang_chan'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        chan_t = StructureBuilder.create()
        type_t = get_type_from_tb(bv, GolangTypeBuilder)
        direction_t = get_type_from_tb(bv, ChanDirectionTBuilder)
        chan_t.append(PointerType.create(bv.arch, type_t), 'Elem')
        chan_t.append(direction_t, 'Dir')
        return chan_t


# src/runtime/map.go
@register_type
class MapBmapTBuilder(GolangTypeBuilderABC):
    base = 'golang_map_bmap'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        map_bmap_t = StructureBuilder.create()
        # golang/go/src/internal/abi/map.go
        MapBucketCountBits = 3
        MapBucketCount = 1 << MapBucketCountBits
        MapMaxKeyBytes = 128
        MapMaxElemBytes = 128

        map_bmap_t.append(ArrayType.create(
            IntegerType.create(1, False),
            MapBucketCount
        ), 'extra')
        return map_bmap_t


@register_type
class MapExtraTBuilder(GolangTypeBuilderABC):
    base = 'golang_map_extra'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        map_extra_t = StructureBuilder.create()
        bmap_t = get_type_from_tb(bv, MapBmapTBuilder)
        bmap_ptr = PointerType.create(bv.arch, bmap_t)
        bmap_ptr_ptr = PointerType.create(bv.arch, bmap_ptr)
        map_extra_t.append(bmap_ptr_ptr, 'overflow')
        map_extra_t.append(bmap_ptr_ptr, 'old_overflow')
        map_extra_t.append(bmap_ptr, 'next_overflow')
        return map_extra_t


@register_type
class MapTBuilder(GolangTypeBuilderABC):
    base = 'golang_map'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        map_t = StructureBuilder.create()
        void_ptr = PointerType.create(bv.arch, VoidType.create())
        map_t.append(IntegerType.create(bv.arch.address_size, False), 'count')
        map_t.append(IntegerType.create(1, False), 'flags')
        map_t.append(IntegerType.create(1, False), 'B')
        map_t.append(IntegerType.create(2, False), 'noverflow')
        map_t.append(IntegerType.create(4, False), 'hash')

        map_t.append(void_ptr, 'buckets')
        map_t.append(void_ptr, 'oldbuckets')
        map_t.append(void_ptr, 'nevacuate')

        map_extra_t = get_type_from_tb(bv, MapExtraTBuilder)

        map_t.append(PointerType.create(
            bv.arch,
            map_extra_t
        ), 'extra')

        return map_t


@register_type
class ChanDirectionTypeTBuilder(GolangTypeBuilderABC):
    base = 'golang_chan_direction_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:

        types = [(etype.name, etype.value) for etype in ChanDirectionType]
        et = Type.enumeration(members=types, width=1)
        return et


@register_type
class ChanTypeTBuilder(GolangTypeBuilder):
    base = 'golang_chan_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        bt = super().build_type(bv, go_version)
        chan_type_t: StructureBuilder = bt.mutable_copy()
        type_t = get_type_from_tb(bv, GolangTypeBuilder)
        direction_t = get_type_from_tb(bv, ChanDirectionTypeTBuilder)
        chan_type_t.append(PointerType.create(bv.arch, type_t), 'Elem')
        chan_type_t.append(direction_t, 'Dir')
        return chan_type_t


@register_type
class SliceTypeTBuilder(GolangTypeBuilder):
    base = 'golang_slice_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        bt = super().build_type(bv, go_version)
        slice_type_t: StructureBuilder = bt.mutable_copy()
        type_t = get_type_from_tb(bv, GolangTypeBuilder)
        slice_type_t.append(PointerType.create(bv.arch, type_t), 'elem')
        return slice_type_t


@register_type
class ArrayTypeTBuilder(GolangTypeBuilder):
    base = 'golang_array_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        bt = super().build_type(bv, go_version)
        array_type_t: StructureBuilder = bt.mutable_copy()
        type_t = get_type_from_tb(bv, GolangTypeBuilder)
        array_type_t.append(PointerType.create(bv.arch, type_t), 'elem')
        array_type_t.append(PointerType.create(bv.arch, type_t), 'slice')
        array_type_t.append(IntegerType.create(bv.arch.address_size), 'len')
        return array_type_t


@register_type
class FuncTypeTBuilder(GolangTypeBuilder):
    base = 'golang_func_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder, StructureBuilder]:
        bt = super().build_type(bv, go_version)
        func_type_t: StructureBuilder = bt.mutable_copy()
        func_type_t.append(IntegerType.create(width=2), 'inCount')
        func_type_t.append(IntegerType.create(width=2), 'outCount')
        return func_type_t

    def build_type_from_gtype(self, bv, gtype: FuncType) -> tuple[Union[Type, StructureBuilder], str]:
        func_type: StructureBuilder = self.build_type(bv, gtype.version)
        type_name = f"golang_func_type"
        if gtype.has_uncommon:
            uncommon_type_t = get_type_from_tb(bv, UncommonTypeBuilder)
            func_type.append(uncommon_type_t, 'uncommon_type')
            type_name += UncommonTypeBuilder.sfx
        type_ptr_t = PointerType.create(bv.arch, get_type_from_tb(bv, GolangStructTypeBuilder))

        if gtype.in_count:
            in_params = Type.array(type_ptr_t, gtype.in_count)
            func_type.append(in_params, 'in_params')
            type_name += f"i[{gtype.in_count}]"
        if gtype.out_count:
            out_params = Type.array(type_ptr_t,  gtype.out_count)
            func_type.append(out_params, 'out_params')
            type_name += f"o[{gtype.in_count}]"
        # FIXME Explore why the parsing of the uncommon type on functions breaks everything.
        #  Because you can have them on functions, as for example this code:
        #  func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        #     if err := fn(w, r); err != nil {
        #         http.Error(w, err.Error(), 500)
        #     }
        #  }
        #  This does not have an high priority since for now the function parsing is only useful for other types
        # if gtype.has_uncommon:
        #     method_t = get_type_from_tb(bv, MethodTypeTBuilder)
        #     method_array = ArrayType.create(method_t, gtype.uncommon_type.mcount)
        #     func_type.append(method_array, 'uncommon_methods')
        type_name += '_t'

        return func_type, type_name


@register_type
class PtrTypeTBuilder(GolangTypeBuilder):
    base = 'golang_ptr_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        bt = super().build_type(bv, go_version)
        ptr_type_t: StructureBuilder = bt.mutable_copy()
        type_t = get_type_from_tb(bv, GolangTypeBuilder)
        ptr_type_t.append(PointerType.create(bv.arch, type_t), 'elem')
        return ptr_type_t

    def build_type_from_gtype(self, bv, gtype: FuncType) -> tuple[Union[Type, StructureBuilder], str]:
        ptr_type: StructureBuilder = self.build_type(bv, gtype.version)
        type_name = self.base
        if gtype.has_uncommon:
            uncommon_type_t = get_type_from_tb(bv, UncommonTypeBuilder)
            ptr_type.append(uncommon_type_t, 'uncommon_type')

            method_t = get_type_from_tb(bv, MethodTypeTBuilder)
            method_array = ArrayType.create(method_t, gtype.uncommon_type.mcount)

            ptr_type.append(method_array, 'uncommon_methods')
            type_name += UncommonTypeBuilder.sfx
        return ptr_type, type_name


@register_type
class UnsafePtrTypeTBuilder(GolangTypeBuilder):
    base = 'golang_unsafe_ptr_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        bt = super().build_type(bv, go_version)
        ptr_type_t: StructureBuilder = bt.mutable_copy()
        ptr_type_t.append(IntegerType.create(bv.arch.address_size, False), 'elem')
        return ptr_type_t

    def build_type_from_gtype(self, bv, gtype: FuncType) -> tuple[Union[Type, StructureBuilder], str]:
        unsafe: StructureBuilder = self.build_type(bv, gtype.version)
        type_name = self.base
        if gtype.has_uncommon:
            uncommon_type_t = get_type_from_tb(bv, UncommonTypeBuilder)
            unsafe.append(uncommon_type_t, 'uncommon_type')
            type_name += UncommonTypeBuilder.sfx
        type_name += '_t'
        return unsafe, type_name


@register_type
class MapTypeTBuilder(GolangTypeBuilder):
    base = 'golang_map_type'
    name = f'{base}_t'

    def build_type(self, bv: bn.BinaryView, go_version: GoVersion = GoVersion.ver118) -> Union[bn.Type, TypeBuilder]:
        bt = super().build_type(bv, go_version)
        map_type_t: StructureBuilder = bt.mutable_copy()
        type_t = get_type_from_tb(bv, GolangTypeBuilder)
        map_type_t.append(PointerType.create(bv.arch, type_t), 'key')
        map_type_t.append(PointerType.create(bv.arch, type_t), 'elem')
        map_type_t.append(PointerType.create(bv.arch, type_t), 'bucket')
        map_type_t.append(PointerType.create(bv.arch, type_t), 'hasher')
        map_type_t.append(IntegerType.create(1, False), 'keysize')
        map_type_t.append(IntegerType.create(1, False), 'valuesize')
        map_type_t.append(IntegerType.create(2, False), 'bucketsize')
        map_type_t.append(IntegerType.create(4, False), 'flags')
        return map_type_t

