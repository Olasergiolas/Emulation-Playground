from qiling import Qiling
import qiling.const as qc
import argparse
from qiling.os.const import *
from challenge1 import challenge1
from challenge2 import challenge2

def challenge3(ql: Qiling, debug: bool = False):
    """
    Reversing the binary showed that the first 32 bytes of /dev/urandom are compared against
    the ones from getrandom() for equalness. A second check verifies that the first and last
    byte read from /dev/urandom are different.
    """
    if debug:
        print("[*] Setting hook for getrandom() and mapping /dev/urandom to file...")

    ql.os.set_api("getrandom", mygetrandom, qc.QL_INTERCEPT.CALL)
    ql.add_fs_mapper("/dev/urandom", "arm64_linux/spoofed_urandom")

def mygetrandom(ql: Qiling):
    params = ql.os.resolve_fcall_params({'buf': POINTER, 'size': SIZE_T, 'flags': UINT})
    ql.mem.write(params["buf"], b"\x41"*params["size"])
    return params["size"]

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

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()