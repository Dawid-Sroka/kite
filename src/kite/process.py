from kite.cpu_context import CPUContext


class Process:
    def __init__(self, cpu_context: CPUContext):
        self.cpu_context = cpu_context
