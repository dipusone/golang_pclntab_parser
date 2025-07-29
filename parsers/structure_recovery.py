import functools

from collections import defaultdict

from ..internal_types.binaryninja_types import *
from ..internal_types.datatypes import GoVersion, TypeName, GolangType, GolangTypeKind, FuncType

from . import TypeParser
from .common import log_error, log_info, log_debug, sanitize_gotype_name, DEBUG, time_it


def fail_gracefully(func):
    @functools.wraps(func,
                     assigned=('cache_info', 'cache_clear'))  # without the assignment the methods are not available
    def wrapped_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_error(f"Fail Gracefully in {func}:\n"
                      f"0x{args[1].address:x}"
                      f" {e}")
            return Type.void()

    return wrapped_function


class StructRecovery(TypeParser):

    def __init__(self, bv: bn.BinaryView, name: str = None, target: int = None):
        super().__init__(bv, name, target)
        self.rodata_addr: Union[int, None] = None
        self.go_version: GoVersion = GoVersion.latest()
        self.already_parsed: set[int] = set()
        self.DEBUG_MISSING_TYPES: dict[str, set] = defaultdict(set)

    def build_types(self):

        log_info("Creating base types and data types")
        data_vars = self.create_types()
        self.already_parsed = set()

        for segment_name in ('.rodata', '__rodata', '.rdata'):
            rodata = self.get_section_by_name(segment_name)
            if rodata:
                break
        else:
            log_error("Unable to find any rodata sections. Terminating")
            return

        self.rodata_addr = rodata.start
        self.go_version = self.quick_go_version()

        log_info("Recovering and defining types")
        type_created = 0
        for data_var in data_vars:
            if data_var in self.already_parsed:
                log_debug(f"Skipping already parsed 0x{data_var:x}")
                continue
            self.already_parsed.add(data_var)
            self.native_type_mapping(data_var)

            type_created += 1
        log_info(f"Created {type_created} native types")

        if DEBUG:
            if  self.DEBUG_MISSING_TYPES:
                log_debug("Missing kind report: ")
            for k, v in self.DEBUG_MISSING_TYPES.items():
                log_debug(k)
                for addr in v:
                    log_debug(f" {hex(addr)}")

        self.already_parsed = set()
        self.DEBUG_MISSING_TYPES = defaultdict(set)
        self.expire_cache()

    @fail_gracefully
    @functools.cache
    def define_struct(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define a struct type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """
        structure = StructureBuilder.create(width=go_data_type['size'].value)
        # Early define for recursive fields
        type_name = self.type_name_from_bn_type(go_data_type)
        self.bv.define_user_type(type_name, structure)
        fields_count = go_data_type['fields']['Len'].value

        # Future self note: you get errors when you try to `enumerate` the fields directly from `struct_fields`. Stick
        #  with `range`
        for idx in range(fields_count):
            field = go_data_type['struct_fields'][idx]
            name_addr = field['name'].value
            offset = field['offset'].value
            field_name = TypeName.from_bv(self.bv,
                                          name_addr,
                                          self.rodata_addr,
                                          self.go_version
                                          )
            type_ptr = field['typ'].value
            # TODO revise this lines of code.
            #  Since all the function are guarded by fail_gracefully this should never happen.
            #  On the other hand we would not get parsing errors so the except clause would never be called
            try:
                field_type = self.native_type_mapping(type_ptr)
                structure.insert(offset, field_type, field_name.name)
            except Exception as e:
                # use only safe fields to avoid having new exceptions
                log_debug(f"Error while parsing the field at 0x{type_ptr:x}, defining as void: {e}")
                structure.insert(offset, Type.void(), f"error_field_{idx}[{field_name}]")

            # Creating and destroying types consumes a metric ton of memory.
            # So the struct definition has been moved at the end.
            # if self.bv.get_type_by_name(type_name):
            #     self.bv.undefine_user_type(type_name)
        # We re-define the type at the end. The parsing of the fields must be safe since if any code raises we
        # lose the entire structure
        self.bv.define_user_type(type_name, structure)
        return self.bv.get_type_by_name(type_name).registered_name

    @fail_gracefully
    @functools.cache
    def define_array(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define an array type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        go_version = self.go_version
        rodata = self.rodata_addr
        array_content_type_gotype = GolangType.from_bv(self.bv,
                                                       go_data_type['elem'].value,
                                                       rodata,
                                                       go_version
                                                       )
        array_field_type = self.native_type_mapping(array_content_type_gotype.address)
        length = go_data_type['len'].value
        return Type.array(array_field_type, length)

    @fail_gracefully
    @functools.cache
    def define_ptr(self, go_data_type: bn.DataVariable, type_suffix='_ptr') -> Type:
        """
        Parse and define a pointer type

        :param go_data_type: the data variable to parse
        :param type_suffix: the suffix to append at the end of the type name
        :return: a binaryninja Type of the data variable
        """

        go_version = self.go_version
        rodata = self.rodata_addr
        pointed_type_gotype = GolangType.from_bv(self.bv,
                                                 go_data_type['elem'].value,
                                                 rodata,
                                                 go_version
                                                 )
        pointed_type_name = self.type_name_from_gotype(pointed_type_gotype)

        # Check if we are pointing to an already defined type
        pointed_type = self.bv.get_type_by_name(pointed_type_name)

        # if the pointed type does not exist try to define it
        if not pointed_type:
            pointed_type = self.native_type_mapping(pointed_type_gotype.address)

        golang_type = PointerType.create(self.bv.arch, pointed_type)
        type_name = f"{pointed_type_name}{type_suffix}"
        self.bv.define_user_type(type_name, golang_type)
        return self.bv.get_type_by_name(type_name)

    @fail_gracefully
    @functools.cache
    def define_base_types(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define base types like strings, slices and maps

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """
        go_version = self.go_version
        rodata = self.rodata_addr
        gotype = GolangType.from_bv(self.bv,
                                    go_data_type.address,
                                    rodata,
                                    go_version
                                    )
        kind_unmasked = GolangTypeKind.unmask(gotype.kind)

        # if everything fails return a void ptr
        tb = PointerType.create(self.bv.arch, Type.void())
        if GolangTypeKind.base_type(kind_unmasked):
            tb = get_type_from_base_type_name(self.bv, kind_unmasked.name.lower())
        elif kind_unmasked is GolangTypeKind.STRING:
            tb = get_type_from_tb(self.bv, StringTBuilder)
        elif kind_unmasked is GolangTypeKind.SLICE:
            tb = get_type_from_tb(self.bv, SliceTBuilder)
        elif kind_unmasked is GolangTypeKind.UNSAFEPTR:
            tb = get_type_from_tb(self.bv, UnsafePtrTBuilder)
        elif kind_unmasked is GolangTypeKind.MAP:
            # Yep seems like maps are always ptr
            tb = PointerType.create(
                self.bv.arch,
                get_type_from_tb(self.bv, MapTBuilder)
            )
        else:
            DEBUG and self.DEBUG_MISSING_TYPES[kind_unmasked.name].add(go_data_type.address)

        return tb

    @fail_gracefully
    @functools.cache
    def define_interface(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define an interface type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        interface = StructureBuilder.create(width=go_data_type['size'].value)
        # TODO for now some fields of the interface struct are unknown to me
        #   For now make them void ptr to something
        ptr_size = self.bv.arch.address_size
        type_name = self.type_name_from_bn_type(go_data_type)
        # first might be pointer to type Interface
        for idx in range(go_data_type['size'].value // ptr_size):
            if idx == 0:
                interface.append(PointerType.create(self.bv.arch,
                                                    Type.void()),
                                 "interface_type_definition"
                                 )
            else:
                interface.append(PointerType.create(self.bv.arch,
                                                    Type.void()),
                                 f"unk_{idx}"
                                 )
        type_name = f"{type_name}_interface"
        self.bv.define_user_type(type_name, interface)
        return self.bv.get_type_by_name(type_name)

    @fail_gracefully
    @functools.cache
    def define_chan(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define a channel type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        # Chan, like maps, tend to be ptr
        type_name = self.type_name_from_bn_type(go_data_type)
        type_name = f"golang_chan_{type_name}_t"
        tb = get_type_from_tb(self.bv, ChanTBuilder)
        self.bv.define_user_type(type_name, tb)
        # TODO find a better way to name the chan
        named_type = self.bv.get_type_by_name(type_name)
        return PointerType.create(self.bv.arch, named_type.registered_name)

    @fail_gracefully
    @functools.cache
    def define_func(self, go_data_type: bn.DataVariable) -> Type:
        """
        Parse and define a func type

        :param go_data_type: the data variable to parse
        :return: a binaryninja Type of the data variable
        """

        late_define = False
        go_version = self.go_version
        rodata = self.rodata_addr
        gotype = FuncType.from_bv(self.bv,
                                  go_data_type.address,
                                  rodata,
                                  go_version
                                  )
        out_type = Type.void()
        if gotype.out_params:
            out_param = gotype.out_params[0]
            if gotype.address == out_param:
                # if the return type is ourselves, short circuit
                log_debug(f"Function type self pointing, short circuiting at 0x{out_param:x}")
                # If we are pointing to ourselves, define the function, then redefine it
                out_type = None
                late_define = True
            else:
                out_type = self.native_type_mapping(out_param)

        in_types = []
        # TODO check variadic args
        #   For variadic functions last parameter seems to be a slice
        #   For now set the function as variadic
        for in_type in gotype.in_params:
            if in_type == gotype.address:
                log_debug("Self pointing, short circuiting")
                continue
            in_types.append(self.native_type_mapping(in_type))

        ft = Type.function(ret=out_type,
                           params=in_types,
                           variable_arguments=gotype.variadic)
        if late_define:
            ft = Type.function(ret=out_type,
                               params=in_types,
                               variable_arguments=gotype.variadic)
        return PointerType.create(self.bv.arch, ft)

    @fail_gracefully
    @functools.cache
    def native_type_mapping(self, address) -> Type:
        """
        Entry point for the creation ot the types. It will check and branch out calling the proper sub-parsers.
        Subparses might call this functions to define their subfield, as for example the content of an array
        or the fields of a struct

        :param address: the address of the type definition
        :return: a binaryninja Type at the address
        """

        go_version = self.go_version
        ro_start = self.rodata_addr

        gotype = GolangType.from_bv(self.bv,
                                    address,
                                    ro_start,
                                    go_version
                                    )

        go_data_type = self.bv.get_data_var_at(address)

        # We might encounter a variable which we did not define before
        # example 0x04a7380 in main-1.2
        if not go_data_type:
            log_debug(f"Datavar at 0x{address:x} does not exist. Defining it now")
            self.target = address
            self.create_types()
            go_data_type = self.bv.get_data_var_at(address)
        kind_unmasked = GolangTypeKind.unmask(gotype.kind)

        if kind_unmasked is GolangTypeKind.ARRAY:
            return self.define_array(go_data_type)
        elif kind_unmasked is GolangTypeKind.PTR:
            return self.define_ptr(go_data_type)
        elif kind_unmasked is GolangTypeKind.STRUCT:
            return self.define_struct(go_data_type)
        elif kind_unmasked is GolangTypeKind.CHAN:
            return self.define_chan(go_data_type)
        elif kind_unmasked is GolangTypeKind.FUNC:
            return self.define_func(go_data_type)
        elif kind_unmasked is GolangTypeKind.INTERFACE:
            return self.define_interface(go_data_type)
        return self.define_base_types(go_data_type)

    def type_name_from_gotype(self, gotype: GolangType) -> str:
        type_name = TypeName.from_bv(self.bv,
                                     gotype.resolved_name_addr,
                                     self.rodata_addr,
                                     self.go_version
                                     )
        return sanitize_gotype_name(type_name.name)

    def type_name_from_bn_type(self, gotype: bn.DataVariable) -> str:
        name_offset = gotype['nameoff'].value
        if self.go_version is not GoVersion.ver12:
            name_offset += self.rodata_addr

        type_name = TypeName.from_bv(self.bv,
                                     name_offset,
                                     self.rodata_addr,
                                     self.go_version
                                     )
        return sanitize_gotype_name(type_name.name)

    def expire_cache(self) -> int:
        cleared_count = 0

        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if callable(attr) and hasattr(attr, 'cache_clear'):
                if DEBUG and hasattr(attr, 'cache_info'):
                    cache_info = attr.cache_info()
                    log_debug(f"{attr_name}: hits={cache_info.hits}, misses={cache_info.misses}")
                attr.cache_clear()
                cleared_count += 1

        return cleared_count

    def run(self):
        self.build_types()
