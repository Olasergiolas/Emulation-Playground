from qiling import Qiling
import qiling.const as qc
import argparse
from qiling.os.const import *
from challenge1 import challenge1
from challenge2 import challenge2
from challenge3 import challenge3
from challenge4 import challenge4
from challenge5 import challenge5
from challenge6 import challenge6
from challenge7 import challenge7
from challenge8 import challenge8
from challenge9 import challenge9

def challenge10(ql: Qiling, debug: bool = False):
    ql.add_fs_mapper("/proc/self/cmdline", "arm64_linux/spoofed_cmdline")

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
    challenge7(ql)
    challenge8(ql, args.debug)
    challenge9(ql, args.debug)
    challenge10(ql, args.debug)

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()