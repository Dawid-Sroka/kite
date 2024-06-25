from kite.cpu_context import CPUContext, VMAreas, M_READ_ONLY, M_READ_WRITE

from pyrisc.sim.snurisc import SNURISC as CPU
from pyrisc.sim.sim import Event

class Simulator:
    def __init__(self, cpu: CPU):
        self.cpu = cpu
        # other hw components like keyboard

    @classmethod
    def create(cls):
        vm = VMAreas()
        cpu = CPU(vm)
        return cls(cpu)

    def load_context_into_cpu(self, cpu_context: CPUContext) -> None:
        self.cpu.pc = cpu_context.pc
        self.cpu.regs = cpu_context.regs
        self.cpu.mmu.page_table = cpu_context.vm

    def read_context_from_cpu(self) -> CPUContext:
        return CPUContext(self.cpu.pc, self.cpu.regs, self.cpu.mmu.page_table)

    def run(self) -> Event:
        return self.cpu.run(self.cpu.pc.read())
