from pyrisc.sim.sim import Event

from typing import Protocol

class CPUContext(Protocol):
    def reg_read(self, reg):
        ...

    def reg_write(self, reg, value):
        ...

class Simulator(Protocol):
    def get_initial_context(self) -> CPUContext:
        ...

    def load_context_into_cpu(self, context: CPUContext) -> None:
        ...

    def read_context_from_cpu(self) -> CPUContext:
        ...

    def run(self) -> Event:
        ...

    def reg_read(self, reg):
        ...

    def reg_write(self, reg, value):
        ...
