from qiling import Qiling
from qiling.exception import *

def memmap(ql: Qiling, addr: int = None, size: int = 0, pagesize: int = 4096):
    try:
        if addr:
            ql.mem.map(addr//pagesize*pagesize, size*pagesize)
        else:
            ql.mem.map_anywhere(size*pagesize)
    except QlMemoryMappedError:
        return 1

    return 0