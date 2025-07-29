import importlib
from go_fix import golang_parser

import parsers.type_parser

importlib.reload(golang_parser)
# fn = golang_parser.FunctionRenamer(bv)
# fn.run()
# pf = golang_parser.PrintFiles(bv)
# pf.run()
tp = parsers.type_parser.TypeParser(bv)
tp.run()
tp.join()