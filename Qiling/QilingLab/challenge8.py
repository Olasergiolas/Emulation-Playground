from qiling import Qiling
import qiling.const as qc
import argparse
import ctypes
from qiling.os.const import *
from challenge1 import challenge1
from challenge2 import challenge2
from challenge3 import challenge3
from challenge4 import challenge4
from challenge5 import challenge5
from challenge6 import challenge6
from challenge7 import challenge7

class unkStruct(ctypes.Structure):
    _fields_ = [
        ("ptr1", ctypes.c_void_p),
        ("n1", ctypes.c_int32),
        ("n2", ctypes.c_int32),
        ("ptr2", ctypes.c_void_p),
    ]

    def __repr__(self) -> str:
        ret = ""
        for field in self._fields_:
            ret += f"{field[0]}: {hex(getattr(self, field[0]))}\n"

        return ret

def challenge8(ql: Qiling, debug: bool = False):
    ql.hook_address(tamper_struct, ql.mem.get_lib_base("qilinglab-aarch64") + 0x11e4, user_data=debug)

def tamper_struct(ql: Qiling, debug: bool = False):
    """
    The challenge function is passed a pointer pointing somewhere in the stack. A struct is
    malloced and its pointer is returned by the function. The field 'ptr2' of the struct is
    set by the challenge function to be the initial value of the pointer passed to it ('arg1').
    The checker function then reads a byte from the intial argument (a.k.a 'ptr2') and checks if it
    is 1. If it is, the challenge is passed.
    """

    struct_ptr = ql.arch.regs.x0
    struct_content = ql.mem.read(struct_ptr, ctypes.sizeof(unkStruct))
    #ptr1, n1, n2, ptr2 = unpack("<QIIQ", struct_content)   # This would be equivalent
    parsed_struct = unkStruct.from_buffer(struct_content)
    
    if debug:
        print("[*] Performing Challenge 8 hooks!")
        print("[*] Parsed struct:\n{}".format(parsed_struct))
        print("[*] Final bytestring after writing to 'ptr2' {}".format(bytes(parsed_struct).hex()))

    ql.mem.write(parsed_struct.ptr2, ql.pack8(1))

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

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()