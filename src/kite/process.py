from kite.cpu_context import CPUContext
from sys import stdin, stdout

class Process:
    def __init__(self, cpu_context: CPUContext):
        self.cpu_context = cpu_context
        self.pid = -1
        self.ppid = -1
        self.fdt = {0: stdin, 1: stdout}
        self.pending_signals = [0]

class ProcessTable:
    def __init__(self):
        self.table = {}
        self.max_pid = 0

    def add(self, process: Process):
        new_pid =  self.max_pid + 1
        self.table[new_pid] = process

class Pipe:
    def __init__(self):
        self.buffer_size = 10
        self.buffer = [None] * self.buffer_size
        self.write_position = 0
        self.read_position = 0
        self.unread_count = 0

    def read(self, n_to_read):
        bytes_read = []
        for _ in range(min(n_to_read, self.unread_count)):
            bytes_read.append(self.buffer[self.read_position])
            self.buffer[self.read_position] = None
            self.read_position = (self.read_position + 1) % self.buffer_size
            self.unread_count -= 1
        return bytes_read

    def write(self, bytes_to_write):
        for i in range(min(self.buffer_size - self.unread_count, len(bytes_to_write))):
            self.buffer[self.write_position] = bytes_to_write[i]
            self.write_position = (self.write_position + 1) % self.buffer_size
            self.unread_count += 1
