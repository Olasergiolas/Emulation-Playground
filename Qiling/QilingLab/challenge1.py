from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.exception import *
from utils import *
import struct

def challenge1(ql: Qiling):
    try:
        memmap(ql, 0x1337, 4)
        ql.mem.write(0x1337, struct.pack("<I", 1337))

    except QlMemoryMappedError:
        print("[!] Error while mapping memory")
        exit(1)

def main():
    # set up command line argv and emulated os root path
    argv = [r'arm64_linux/qilinglab-aarch64']
    rootfs = r'arm64_linux/'

    # instantiate a Qiling object using above arguments and set emulation verbosity level to DEBUG.
    ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.DISABLED)

    challenge1(ql)

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()