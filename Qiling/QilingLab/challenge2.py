from qiling import Qiling
import qiling.const as qc
import argparse
from qiling.os.const import *
from challenge1 import challenge1

UTSNAME_ENTRY_SIZE = 65
UTSNAME_SIZE: int = UTSNAME_ENTRY_SIZE*3

def challenge2(ql: Qiling, debug: bool = False):
    if debug:
        print("[*] Enabling hooks for challenge2...")
        modbase: int = ql.mem.get_lib_base("qilinglab-aarch64")
        print("[*] BASE: {}".format(hex(modbase)))
        ql.hook_address(check_strlen, modbase + 0xe2c)  # Equal char length check for "QilingOS"
        ql.hook_address(check_strlen, modbase + 0xe40)  # Equal char length check for "ChallengeStart"
        ql.hook_address(check_char_compare, modbase + 0xd9c) # Individual char compare for "QilingOS"
        ql.hook_address(check_char_compare, modbase + 0xdec) # Individual char compare for "ChallengeStart"
    
    print("[*] Spoofing uname syscall")
    ql.os.set_api("uname", my_uname, qc.QL_INTERCEPT.CALL)  # Override implementation entirely

def my_uname(ql: Qiling):
    params = ql.os.resolve_fcall_params({'buf': POINTER})
    uname_os_str: str = "QilingOS"
    uname_version_str: str = "ChallengeStart"

    addr = params["buf"]
    ql.mem.write(addr, b"\x00" * UTSNAME_SIZE)
    ql.mem.string(addr, uname_os_str)
    ql.mem.string(addr + UTSNAME_ENTRY_SIZE*3, uname_version_str)

    ql.arch.regs.x0 = 0

    return 0

def check_strlen(ql: Qiling):
    print("[*] Comparing final results!")
    print("x19: {}".format(ql.arch.regs.x19))
    print("x0: {}".format(hex(ql.arch.regs.x0)))
    print()

def check_char_compare(ql: Qiling):
    print("[*] x0: {} - x1: {}".format(chr(ql.arch.regs.x0), chr(ql.arch.regs.x1)))

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

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()