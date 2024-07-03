from kite.cpu_context import CPUContext
from sys import stdin, stdout

class Process:
    def __init__(self, cpu_context: CPUContext):
        self.cpu_context = cpu_context
        self.pid = -1
        self.fdt = {0: stdin, 1: stdout}

class ProcessTable:
    def __init__(self):
        self.table = {}
        self.max_pid = 0

    def add(self, process: Process):
        new_pid =  self.max_pid + 1
        self.table[new_pid] = process
