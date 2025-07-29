from binaryninja import BinaryView

from .type_parser import TypeParser
from .functions_renamer import FunctionRenamer, FunctionCommenter
from .file_printer import PrintFiles
from .run_all import RunAll, RunAllWithStructureRecovery
from .structure_recovery import StructRecovery
from .goresym_parser import GoReSymImporter, GoResSymExecutor


def rename_functions(bv: BinaryView):
    helper = FunctionRenamer(bv)
    return helper.start()


def goresym_import(bv: BinaryView):
    helper = GoReSymImporter(bv)
    return helper.start()


def goresym_run_and_import(bv: BinaryView):
    helper = GoResSymExecutor(bv)
    return helper.start()


def create_types(bv: BinaryView):
    helper = TypeParser(bv)
    return helper.start()


def create_type_at_address(bv, address):
    helper = TypeParser(bv, target=address)
    return helper.start()


def create_structures(bv: BinaryView):
    helper = StructRecovery(bv)
    return helper.start()


def create_structures_at_address(bv, address):
    helper = StructRecovery(bv, target=address)
    return helper.start()


def print_files(bv: BinaryView):
    helper = PrintFiles(bv)
    return helper.start()


def comment_functions(bv: BinaryView):
    helper = FunctionCommenter(bv)
    return helper.start()


def parse_go_file(bv: BinaryView):
    ra = RunAll(bv)
    return ra.start()


def parse_go_file_w_structures(bv: BinaryView):
    ra = RunAllWithStructureRecovery(bv)
    return ra.start()
