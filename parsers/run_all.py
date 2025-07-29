import binaryninja as bn

from .common import NAME, log_info
from .functions_renamer import FunctionRenamer, FunctionCommenter
from .type_parser import TypeParser
from .structure_recovery import StructRecovery


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


class RunAllWithStructureRecovery(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__(NAME, True)
        self.bv = bv
        self.analysis = []
        self.analysis.append(FunctionRenamer(bv))
        self.analysis.append(FunctionCommenter(bv))
        self.analysis.append(StructRecovery(bv))

    def run(self):
        for analysis in self.analysis:
            analysis.start()
            analysis.join()
        log_info(f"Terminated all analysis")
