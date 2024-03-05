from pyrisc.sim.components import Register, RegisterFile, Memory
from kite.consts import *


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
    def __init__(self, pc: Register, registers: RegisterFile, imem: Memory, dmem: Memory):
        self.pc = pc
        self.registers = registers
        self.imem = imem
        self.dmem = dmem

    @classmethod
    def create(cls):
        pc = Register()
        registers = RegisterFile()
        imem   = Memory(IMEM_START, IMEM_SIZE, WORD_SIZE)
        dmem   = Memory(DMEM_START, DMEM_SIZE, WORD_SIZE)
        return cls(pc, registers, imem, dmem)
