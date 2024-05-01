from qiling import Qiling
import qiling.const as qc
import argparse
from qiling.os.const import *
from unicorn.arm64_const import *
from unicorn.arm_const import *
import lief
from capstone import *
from challenge1 import challenge1
from challenge2 import challenge2
from challenge3 import challenge3
from challenge4 import challenge4
from challenge5 import challenge5
from challenge6 import challenge6
from challenge7 import challenge7
from challenge8 import challenge8
from challenge9 import challenge9
from challenge10 import challenge10

def challenge11(ql: Qiling, debug: bool = False):
    modbase = ql.mem.get_lib_base("qilinglab-aarch64")
    mod_elf: lief.Binary = lief.parse("arm64_linux/qilinglab-aarch64")
    challenge11_func = next(i for i in mod_elf.symbols if i.name == "challenge11")  # There is no such thing as a get_function_by_name method in lief
    challenge11_func_addr = challenge11_func.value                                  # Use .symbols instead of .exported_functions because lief screw up
    challenge11_func_end = challenge11_func_addr + challenge11_func.size            # the symbol size if using the Function object.
    ql.hook_code(callback=mrs_callback, begin=modbase+challenge11_func_addr, end=modbase+challenge11_func_end-0x4)  # .hook_insn() is not properly working

def mrs_callback(ql: Qiling, address, size):
    instruction = ql.mem.read(address, 4)
    parsed_inst = ql.arch.disassembler.disasm_lite(instruction, 4, count=1)
    for i in parsed_inst:
        if i[2] == "mrs":   # Disassembler returns a tuple of (address, size, mnemonic, op_str)
            ql.arch.regs.x0 = (0x1337 << 0x10)
            ql.arch.regs.arch_pc += 0x4

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
    challenge11(ql, args.debug)

    # do the magic!
    ql.run()

if __name__ == "__main__":
    main()