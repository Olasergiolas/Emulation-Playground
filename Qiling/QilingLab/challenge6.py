from qiling import Qiling
import qiling.const as qc
import argparse
from qiling.os.const import *
from challenge1 import challenge1
from challenge2 import challenge2
from challenge3 import challenge3
from challenge4 import challenge4
from challenge5 import challenge5

def challenge6(ql: Qiling):
    ql.hook_address(avoid_loop, ql.mem.get_lib_base("qilinglab-aarch64") + 0x1118)

def avoid_loop(ql: Qiling):
    ql.arch.regs.x0 = 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action="store_true")
    args = parser.parse_args()

    # set up command line argv and emulated os root path
    argv = [r'arm64_linux/qilinglab-aarch64']
    rootfs = r'arm64_linux/'

    # instantiate a Qiling object using above arguments and set emulation verbosity level to DEBUG.
    ql = Qiling(argv, rootfs, verbose=qc.QL_VERBOSE.OFF)
    #ql.debugger = "gdb"

    challenge1(ql)
    challenge2(ql, args.debug)
    challenge3(ql, args.debug)
    challenge4(ql, args.debug)
    challenge5(ql)
    challenge6(ql)

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()