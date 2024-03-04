from pyrisc.sim.components import Register, RegisterFile


class CPUContext:
    def __init__(self, pc: Register, registers: RegisterFile):
        self.pc = pc
        self.registers = registers
