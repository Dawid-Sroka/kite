from kite.cpu_context import CPUContext


class Process:
    def __init__(self, vm_areas, cpu_context: CPUContext):
        self.vm_areas = vm_areas
        self.cpu_context = cpu_context

class ProcessTable:
    def __init__(self):
        self.table = {}
        self.max_pid = 0

    def add(self, process: Process):
        new_pid =  self.max_pid + 1
        self.table[new_pid] = process
