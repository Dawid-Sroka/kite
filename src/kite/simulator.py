from kite.cpu_context import CPUContext

from pyrisc.sim.snurisc import SNURISC as CPU
from pyrisc.sim.sim import Event

class Simulator:
    def __init__(self, cpu: CPU):
        self.cpu = cpu

    @classmethod
    def create(cls):
        cpu = CPU()
        return cls(cpu)

    def load_context_into_cpu(self, cpu_context: CPUContext) -> None:
        self.cpu.pc = cpu_context.pc
        self.cpu.regs = cpu_context.regs
        self.cpu.page_table = cpu_context.page_table

    def read_context_from_cpu(self) -> CPUContext:
        return CPUContext(self.cpu.pc, self.cpu.regs, self.cpu.page_table)

    def run(self) -> Event:
        return self.cpu.run(self.cpu.pc.read())
