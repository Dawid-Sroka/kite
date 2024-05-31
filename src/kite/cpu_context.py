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

class CPUContext:
    def __init__(self, pc: Register, regs: RegisterFile, imem: Memory, dmem: Memory, pt: PageTable):
        self.pc = pc
        self.regs = regs
        self.imem = imem
        self.dmem = dmem
        self.page_table = pt

    @classmethod
    def create(cls):
        pc = Register()
        regs = RegisterFile()
        imem   = Memory(IMEM_START, IMEM_SIZE, WORD_SIZE)
        dmem   = Memory(DMEM_START, DMEM_SIZE, WORD_SIZE)
        page_table = PageTable()
        return cls(pc, regs, imem, dmem, page_table)
