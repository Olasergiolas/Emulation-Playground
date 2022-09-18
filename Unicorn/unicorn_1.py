from unicorn import *
from unicorn.x86_const import *

# x64 code that just iterates over a given string incrementing each character by one
ARM_CODE   = b'\x55\x48\x89\xe5\x48\x89\x7d\xe8\xc7\x45\xfc\x00\x00\x00\x00\xeb\x22\x8b\x55\xfc\x48\x8b\x45\xe8\x48\x01\xd0\x0f\xb6\x00\x8d\x48\x01\x8b\x55\xfc\x48\x8b\x45\xe8\x48\x01\xd0\x89\xca\x88\x10\x83\x45\xfc\x01\x83\x7d\xfc\x03\x76\xd8\x48\x8b\x45\xe8\x5d'
PAYLOAD    = b'\x41\x42\x43\x44'

ADDRESS         = 0x10001000
ADDRESS_PAYLOAD = 0x210000
STACK           = 0x3000000
HEAP            = 0x6000000
HEAP_SIZE       = 0x10000
STACK_SIZE      = 0x3000
ADDRESS_END     = ADDRESS + len(ARM_CODE)

def setup_stack_heap(mu):
    # Map memory for stack and heap
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(HEAP, HEAP_SIZE)
    mu.mem_map(0, 0x1000)
    
    # Setup RSP/RBP including a stack frame
    mu.reg_write(UC_X86_REG_RSP, STACK + STACK_SIZE -4 - 0x200)
    mu.reg_write(UC_X86_REG_RBP, STACK + STACK_SIZE -4)
    
def setup_code(mu):
    # Map code and input parameters
    mu.mem_map(ADDRESS, 0x1000000)
    mu.mem_map(ADDRESS_PAYLOAD, 0x1000)
    
    # Write code and input parameters to memory
    mu.mem_write(ADDRESS, ARM_CODE)
    mu.mem_write(ADDRESS_PAYLOAD, PAYLOAD)
    
    # Set registers accordingly (Watch out for the calling convention being used!)
    mu.reg_write(UC_X86_REG_RIP, ADDRESS)
    mu.reg_write(UC_X86_REG_RDI, ADDRESS_PAYLOAD)

def process_results(mu):
    rax = mu.reg_read(UC_X86_REG_RAX)
    print("[*] RAX = 0x%x" %rax)
    res = mu.mem_read(ADDRESS_PAYLOAD, len(PAYLOAD))
    print(res)

def main():
    try:
        # Initialize Unicorn
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        setup_stack_heap(mu)
        setup_code(mu)
        mu.emu_start(ADDRESS, ADDRESS_END)

        # Get results
        print("[*] Emulation completed!")
        process_results(mu)

    except UcError as e:
        print("[*]UC ERROR: %s" % e)

if __name__ == '__main__':
    main()