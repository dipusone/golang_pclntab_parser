from ..internal_types.binaryninja_types import *
from ..internal_types.datatypes import *

from .common import GoHelper, log_info, log_debug, log_error, log_warn, sanitize_gotype_name, santize_gofunc_name


class TypeParser(GoHelper):
    TYPED = [
        'runtime.new',
        'runtime.newobject',
        'runtime.makechan',
        'runtime.makemap',
        'runtime.mapiterinit',
        'runtime.makeslice'
    ]

    TYPE_SUFFIX = "_type"

    RODATA_SECTIIONS = ('.rodata', '__rodata', '.rdata')

    def __init__(self, bv: bn.BinaryView, name: str = None, target: int = None):
        super().__init__(bv, name)
        self.target: int = target
        self.rodata_section: Union[bn.Section, None] = None

    def create_types(self):

        log_info(f"Creating reference types")
        go_version = self.quick_go_version()
        log_debug(f"Go Version is {go_version}")

        already_parsed = set()
        data_vars = set()
        typed_vars = set()

        for segment_name in self.RODATA_SECTIIONS:
            rodata = self.get_section_by_name(segment_name)
            if rodata:
                self.rodata_section = rodata
                break
        else:
            log_error("Unable to find any rodata sections. Terminating")
            return

        def add_to_data_vars(addr: int, parent: int = 0, force=False):
            # FIXME some destination have strange addresses :(
            if addr not in already_parsed and addr in rodata or force:
                data_vars.add((addr, parent))

        created = 0
        exceptions = 0

        # Create base golang type like int, map, etc...
        for type_maker in GOLAND_TYPES:
            name = type_maker.name
            new_type = type_maker().build_type(self.bv, go_version)
            if not new_type:
                log_warn(f"Unable to parse type string {name}")
                continue
            self.bv.define_user_type(name, new_type)

        golang_base_type = self.bv.get_type_by_name(GolangTypeBuilder.name)

        # target is set when the parser is called with an address
        if self.target:
            data_vars.add((self.target, 0))
        else:
            data_vars = self.collect_xrefs()

        log_info("Starting type parsing")
        
        while len(data_vars) > 0:
            log_debug(f"Left {len(data_vars)}")
            data_var_addr, parent = data_vars.pop()
            log_debug(f"Current addr {data_var_addr:x}")

            if data_var_addr in already_parsed:
                log_debug(f"Skipping already parsed at 0x{data_var_addr:x}")
                continue
            already_parsed.add(data_var_addr)

            try:
                gotype = GolangType.from_bv(self.bv,
                                            data_var_addr,
                                            rodata.start,
                                            go_version
                                            )
                # Minimum sanity check
                if not gotype.is_valid(rodata):
                    log_debug(f"Skipping {hex(data_var_addr)} since invalid")
                    continue
                go_data_type = self.bv.get_data_var_at(data_var_addr)

                # TODO add some sanity checks to the datavar before parsing
                #  maybe checking if the equal_fn **points in the executable section or it is zero (if not fn)

                # get_data_var_at will return None on error
                # funny enough `not <void var>` is `True`
                if go_data_type is None:
                    go_data_type = self.bv.define_user_data_var(data_var_addr, golang_base_type)

                if gotype.kind is GolangTypeKind.STRUCT:
                    gotype = StructType.from_bv(self.bv,
                                                go_data_type.address,
                                                rodata.start,
                                                go_version
                                                )
                    for field in gotype.fields_list:
                        add_to_data_vars(field.type_ptr, 0)
                    new_type, name = GolangStructTypeBuilder().build_type_from_gtype(self.bv, gotype)
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type

                elif gotype.kind is GolangTypeKind.ARRAY:
                    gotype = ArrayType.from_bv(self.bv,
                                               go_data_type.address,
                                               rodata.start,
                                               go_version
                                               )
                    new_type, name = ArrayTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    add_to_data_vars(gotype.element_ptr)
                    add_to_data_vars(gotype.slice_ptr)
                elif gotype.kind is GolangTypeKind.CHAN:
                    gotype = ChanType.from_bv(self.bv,
                                              go_data_type.address,
                                              rodata.start,
                                              go_version
                                              )
                    new_type, name = ChanTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.element_ptr)
                elif gotype.kind is GolangTypeKind.SLICE:
                    gotype = SliceTType.from_bv(self.bv,
                                                go_data_type.address,
                                                rodata.start,
                                                go_version
                                                )
                    new_type, name = SliceTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.element_ptr)
                elif gotype.kind is GolangTypeKind.FUNC:
                    # TODO check if it is possible creating a new function when we parse this type
                    #  since there are interesting information (but it might lack the function addr)
                    gotype = FuncType.from_bv(self.bv,
                                              go_data_type.address,
                                              rodata.start,
                                              go_version
                                              )
                    new_type, name = FuncTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    for param in gotype.in_params + gotype.out_params:
                        add_to_data_vars(param)
                elif gotype.kind is GolangTypeKind.PTR:
                    gotype = PtrType.from_bv(self.bv,
                                             go_data_type.address,
                                             rodata.start,
                                             go_version
                                             )
                    new_type, name = PtrTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.element_ptr)
                elif gotype.kind is GolangTypeKind.MAP:
                    gotype = MapType.from_bv(self.bv,
                                             go_data_type.address,
                                             rodata.start,
                                             go_version
                                             )
                    new_type, name = MapTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                    add_to_data_vars(gotype.key)
                    add_to_data_vars(gotype.elem)
                    add_to_data_vars(gotype.bucket)
                # TODO for some strange reason if i parse unsafeptr it will break the array
                elif gotype.kind is GolangTypeKind.INTERFACE:
                    gotype = InterfaceType.from_bv(self.bv,
                                                   go_data_type.address,
                                                   rodata.start,
                                                   go_version
                                                   )
                    new_type, name = InterfaceTypeTBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    for imethod in gotype.methods_array:
                        add_to_data_vars(imethod.resolved_typ, imethod.typ_address)
                    self.bv.define_user_type(name, new_type)
                    go_data_type.type = new_type
                else:
                    # Some unhandled type, so check only for the uncommon type
                    gotype.add_uncommon_type(self.bv,
                                             go_data_type.address + gotype.size_from_bv(self.bv, gotype.address),
                                             )
                    gotype.add_uncommon_methods(self.bv)
                    new_type, name = GolangTypeBuilder().build_type_from_gtype(self.bv, gotype)
                    go_data_type.type = new_type
                    self.bv.define_user_type(name, new_type)

                type_name = TypeName.from_bv(self.bv,
                                             gotype.resolved_name_addr,
                                             rodata.start,
                                             go_version
                                             )
                if go_version == GoVersion.ver12:
                    string_t = Type.named_type_from_registered_type(self.bv, StringTBuilder.name)
                    var = self.bv.get_data_var_at(gotype.resolved_name_addr)
                    if var is None:
                        var = self.bv.define_user_data_var(gotype.resolved_name_addr, golang_base_type)
                    var.type = string_t

                # DEBUG_kinds[gotype.kind.name].append(gotype)
            except Exception as e:
                exceptions += 1
                log_debug(f"Exception: {hex(data_var_addr)}:{e}")
                continue

            for uncommon_method in gotype.uncommon_methods:
                if uncommon_method.mtype != 0xffffffff:
                    add_to_data_vars(rodata.start + uncommon_method.mtype, uncommon_method.address)

            name = type_name.name
            if not name or len(name) == 0:
                log_debug("Invalid Name, skipping")
                continue

            log_debug(f"Found name at 0x{gotype.resolved_name_addr:x} with value {name}")

            sanitazed_name = sanitize_gotype_name(name)
            go_data_type.name = f"{sanitazed_name}{self.TYPE_SUFFIX}"
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
                log_debug(f"Dest will be {hex(gotype.resolved_type_off)}")
                add_to_data_vars(gotype.resolved_type_off, gotype.address_off('typeOff'))

            typed_vars.add(data_var_addr)
            created += 1

        log_info(f"Created {created} go types")
        log_debug(f"  totally parsed sites: {len(already_parsed)}")
        log_debug(f"Exceptions {exceptions}")
        return typed_vars

    def collect_xrefs(self) -> set:
        data_vars = set()
        log_info("Searching for functions accessing type objects")
        log_info(f"Will search for {len(self.TYPED)} functions {','.join(self.TYPED)}")

        for typed_function in self.TYPED:
            functions = self.bv.get_functions_by_name(typed_function)
            if not functions:
                # maybe the name was generated by `FunctionRenamer` and therefore sanitized
                sanitized_typed_function = santize_gofunc_name(typed_function)
                functions = self.bv.get_functions_by_name(sanitized_typed_function)

            for function in functions:
                log_info(f"Parsing function {function.name}")
                if not function.parameter_vars:
                    continue

                # Collect direct references, since after we have to expand the list
                # with the references from typeoff
                for caller_site in function.caller_sites:
                    try:
                        mlil = caller_site.mlil
                    except:
                        log_debug(f"Unable to get the mlil for instruction at 0x{caller_site.address}")
                        continue
                    if not mlil:
                        # This can happen with big functions or functions which binja decided not to analyze
                        log_debug(f"Empty MLIL, skipping caller site at 0x{caller_site.address:x}")
                        continue
                    elif mlil.operation != bn.MediumLevelILOperation.MLIL_CALL:
                        log_debug(f"Callsite at 0x{mlil.address:x} is not a call, skipping")
                        continue
                    # This is very crude, since it works under the assumption that the first parameter points
                    #  to the type definition, but it generally works
                    # Iterate over all the parameter until we found something pointing in rodata
                    #  since binja is not always able to determine the correct calling convention
                    for params in mlil.params:
                        value = params.value.value
                        # if value is not 0 and the value is in the rodata section add ti as a candidate
                        if value and (self.rodata_section and value in self.rodata_section):
                            data_vars.add((value, 0))
                            break
        log_info(f"Found {len(data_vars)} xrefs")
        return data_vars

    def run(self):
        self.create_types()
