from kite.cpu_context import VMAreas
from kite.simulators.simulator import CPUContext

from pyrisc.sim.snurisc import SNURISC as CPU
from pyrisc.sim.sim import Event as PyRISCEvent
from pyrisc.sim.sim import MemEvent as PyRISCMemEvent

from pyrisc.sim.components import Register, RegisterFile

from kite.consts import *

reg_to_pyrisc_reg = {
    REG_RA: 1,
    REG_SP: 2,
    REG_SYSCALL_ARG0: 10,
    REG_SYSCALL_ARG1: 11,
    REG_SYSCALL_ARG2: 12,
    REG_SYSCALL_ARG3: 13,
    REG_SYSCALL_ARG4: 14,
    REG_SYSCALL_ARG5: 15,
    REG_SYSCALL_NUMBER: 17,
    REG_RET_VAL1: 10,
    REG_RET_VAL2: 11,
}

def reg_read(obj, reg):
    if reg == REG_PC:
        return obj.pc.read()
    if reg not in reg_to_pyrisc_reg:
        raise NotImplemented
    pyrisc_reg = reg_to_pyrisc_reg[reg]
    return obj.regs.read(pyrisc_reg)

def reg_write(obj, reg, value):
    if reg == REG_PC:
        obj.pc.write(value)
        return
    if reg not in reg_to_pyrisc_reg:
        raise NotImplemented
    pyrisc_reg = reg_to_pyrisc_reg[reg]
    obj.regs.write(pyrisc_reg, value)

class PyRISCContext:
    def __init__(self, pc: Register, regs: RegisterFile, vm_areas: VMAreas):
        self.pc = pc
        self.regs = regs
        self.vm = vm_areas

    def reg_read(self, reg):
        return reg_read(self, reg)

    def reg_write(self, reg, value):
        reg_write(self, reg, value)

class PyRISCSimulator:
    def __init__(self):
        self.cpu = CPU(VMAreas(32))

    def load_context_into_cpu(self, context: CPUContext) -> None:
        self.cpu.pc = context.pc
        self.cpu.regs = context.regs
        self.cpu.mmu.page_table = context.vm

    def get_initial_context(self) -> CPUContext:
        return PyRISCContext(self.cpu.pc, self.cpu.regs, VMAreas(32))

    def read_context_from_cpu(self) -> CPUContext:
        return PyRISCContext(self.cpu.pc, self.cpu.regs, self.cpu.mmu.page_table)

    def run(self) -> Event:
        event = self.cpu.run(self.cpu.pc.read())
        if isinstance(event, PyRISCMemEvent):
            return MemEvent(event.type, event.fault_addr, event.fault_pc)
        elif isinstance(event, PyRISCEvent):
            return Event(event.type)

    def reg_read(self, reg):
        return reg_read(self.cpu, reg)

    def reg_write(self, reg, value) -> None:
        reg_write(self.cpu, reg, value)

    # this function is not necessary for PyRISC
    def reset_instruction_counter(self):
        pass
