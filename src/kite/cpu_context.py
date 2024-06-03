from pyrisc.sim.components import Register, RegisterFile, Memory
from kite.consts import *

from pyrisc.sim.components import PageTable

#--------------------------------------------------------------------------
#   Configurations
#--------------------------------------------------------------------------

# Memory configurations
#   IMEM: 0x80000000 - 0x8000ffff (64KB)
#   DMEM: 0x80010000 - 0x8001ffff (64KB)

IMEM_START  = WORD(0x80000000)      # IMEM: 0x80000000 - 0x8000ffff (64KB)
IMEM_SIZE   = WORD(64 * 1024)
DMEM_START  = WORD(0x80010000)      # DMEM: 0x80010000 - 0x8001ffff (64KB)
DMEM_SIZE   = WORD(64 * 1024)
#--------------------------------------------------------------------------

class VMAreas:
    def __init__(self):
        self.vm_areas_list = []

class VMAreaStruct:
    def __init__(self, vm_start, vm_end, vm_prot, vm_flags):
        self.vm_start = vm_start
        self.vm_end = vm_end
        self.vm_prot = vm_prot
        self.vm_flags = vm_flags

    def does_contain_address(self, virt_addr):
        if self.vm_start <= virt_addr and virt_addr < self.vm_end:
            return True
        else:
            return False

class CPUContext:
    def __init__(self, pc: Register, regs: RegisterFile, pt: PageTable):
        self.pc = pc
        self.regs = regs
        self.page_table = pt

    @classmethod
    def create(cls):
        pc = Register()
        regs = RegisterFile()
        page_table = PageTable()
        return cls(pc, regs, page_table)
