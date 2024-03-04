from kite.cpu_context import CPUContext

from pyrisc.sim.snurisc import SNURISC as CPU


class Event:
    def __init__(self, exception_type: int):
        self.exc_t = exception_type


class Simulator:
    def __init__(self, cpu: CPU):
        self.cpu = cpu

    @classmethod
    def create(cls):
        cpu = CPU()
        return cls(cpu)

    def load_context_into_cpu(self, cpu_context: CPUContext) -> None:
        self.cpu.pc = cpu_context.pc
        self.cpu.registers = cpu_context.registers
        raise NotImplementedError

    def read_context_from_cpu(self, cpu_context: CPUContext) -> None:
        cpu_context.pc = self.cpu.pc
        cpu_context.registers = self.cpu.registers

    def run(self) -> Event:
        return self.cpu.run(self.cpu.pc.read)
        raise NotImplementedError
