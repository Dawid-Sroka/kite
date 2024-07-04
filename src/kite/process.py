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

class Pipe:
    def __init__(self):
        self.buffer_size = 6
        self.buffer = [None] * self.buffer_size
        self.buffer = [1,2,3,4,5,6]
        self.write_position = 5
        self.read_position = 0

    def read(self, n_to_read):
        available_bytes_cnt = (self.write_position - self.read_position) % self.buffer_size
        bytes_read = [0] * available_bytes_cnt
        for i in range(0, min(n_to_read, available_bytes_cnt)):
            idx = (self.read_position + i) % self.buffer_size
            bytes_read[i] = self.buffer[idx]
        return bytes_read

    def write(self, bytes_to_write):
        available_bytes_cnt = (self.read_position - self.write_position) % self.buffer_size
        for i in range(0, min(available_bytes_cnt, len(bytes_to_write))):
            idx = (self.write_position + i) % self.buffer_size
            self.buffer[idx] = bytes_to_write[i]
