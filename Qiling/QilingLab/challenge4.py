from qiling import Qiling
import qiling.const as qc
import argparse
from qiling.os.const import *
from challenge1 import challenge1
from challenge2 import challenge2
from challenge3 import challenge3

def challenge4(ql: Qiling, debug: bool = False):
    """
    Modify the X1 register so the while condition is met once. Enough
    for it to set the result to 1 and pass the challenge.
    """
    modbase: int = ql.mem.get_lib_base("qilinglab-aarch64")
    ql.hook_address(force_enter_loop, modbase + 0xfe0)

cmp_patched = False
def force_enter_loop(ql: Qiling):
    global cmp_patched

    if not cmp_patched:
        ql.arch.regs.x1 = -1
        cmp_patched = True

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

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()