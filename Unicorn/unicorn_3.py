from unicorn import *
from unicorn.arm_const import *

# ARM version!
# RSP -> SP
# RBP -> FP
ARM_CODE   = b''
PAYLOAD    = b'\x48\x65\x6c\x6c\x6f\x21'

ADDRESS         = 0x10001000
ADDRESS_PAYLOAD = 0x210000
STACK           = 0x3000000
HEAP            = 0x6000000
HEAP_SIZE       = 0x10000
STACK_SIZE      = 0x3000
ADDRESS_START   = ADDRESS + 0x8254

def setup_stack_heap(mu):
    # Map memory for stack and heap
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(HEAP, HEAP_SIZE)
    mu.mem_map(0, 0x1000)
    
    # Setup RSP/RBP including a stack frame
    mu.reg_write(UC_ARM_REG_SP, STACK + STACK_SIZE -4 - 0x200)
    mu.reg_write(UC_ARM_REG_FP, STACK + STACK_SIZE -4)
    
def setup_code(mu, code):
    # Map code and input parameters
    mu.mem_map(ADDRESS, 0x1000000)
    mu.mem_map(ADDRESS_PAYLOAD, 0x1000)
    
    # Write code and input parameters to memory
    mu.mem_write(ADDRESS, code)
    mu.mem_write(ADDRESS_PAYLOAD, PAYLOAD)
    
    # Set registers accordingly (Watch out for the calling convention being used!)
    mu.reg_write(UC_ARM_REG_PC, ADDRESS_START)
    mu.reg_write(UC_ARM_REG_R0, ADDRESS_PAYLOAD)
    
def process_results(mu):
    rax = mu.reg_read(UC_ARM_REG_R0)
    print("[*] R0 = 0x%x" %rax)
    res = mu.mem_read(ADDRESS_PAYLOAD, len(PAYLOAD))
    print(res)
    
def read_bytes(path):
    with open(path, 'rb') as f:
        return f.read()

def main():
    try:
        code = read_bytes('./main_arm')
        
        # Initialize Unicorn
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        setup_stack_heap(mu)
        setup_code(mu, code)
        mu.emu_start(ADDRESS_START, ADDRESS_START + 0x94)

        # Get results
        print("[*] Emulation completed!")
        process_results(mu)

    except UcError as e:
        print("[*]UC ERROR: %s" % e)
        print(mu.reg_read(UC_ARM_REG_PC))

if __name__ == '__main__':
    main()