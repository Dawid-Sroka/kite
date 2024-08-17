from kite.cpu_context import CPUContext
from sys import stdin, stdout, stderr
from abc import ABC, abstractmethod

class Process:
    def __init__(self, cpu_context: CPUContext):
        self.cpu_context = cpu_context
        self.pid = -1
        self.ppid = -1
        self.fdt = {0: OpenFileObject("stdin", stdin),
                    1: OpenFileObject("stdout", stdout),
                    2: OpenFileObject("stderr", stderr)}
        self.pending_signals = [0]

class ProcessTable:
    def __init__(self):
        self.table = {}
        self.max_pid = 0

    def add(self, process: Process):
        new_pid =  self.max_pid + 1
        self.table[new_pid] = process


class Resource:
    def __init__(self, resource_type, resource):
        self.resource_type = resource_type
        self.resource = resource


class OpenFileObject(ABC):
    def __init__(self, file_name, file_struct):
        self.file_struct = file_struct
        self.file_name = file_name

    def read(self, bytes_to_read):
        return self.file_struct.read(bytes_to_read)

    def write(self, bytes_to_read):
        return self.file_struct.read(bytes_to_read)


class RegularFile(OpenFileObject):
    def __init__(self, file_name, file_struct):
        super().__init__(file_name, file_struct)
        self.ref_cnt = 1
        self.position = 0

    def read(self, bytes_to_read):
        f = self.file_struct
        f.seek(self.position)
        chars_read = f.read(bytes_to_read)
        self.position += len(chars_read)
        bytes_read = [ord(b) for b in chars_read]
        return bytes_read

    def write(self, bytes_to_write):
        position = 0
        f = self.file_struct
        f.seek(position)
        f.write("written\n")
        f.flush()


class PipeBuffer():
    def __init__(self, buffer_size):
        self.buffer_size = buffer_size
        self.buffer = [None] * self.buffer_size
        self.write_position = 0
        self.read_position = 0
        self.unread_count = 0

class PipeReadEnd(OpenFileObject):
    def __init__(self, file_name, file_struct):
        super().__init__(file_name, file_struct)
        self.ref_cnt = 1
        self.referenced_by = []
        self.write_end_ptr = None

    def read(self, n_to_read):
        pipe_buffer = self.file_struct
        print("pipe buf: ", self.file_struct.buffer)

        while pipe_buffer.unread_count == 0:
            print("     read blocked! What should happen now?")
            yield ("block", Resource("I/O", self.write_end_ptr))

        chars_read = []
        no_bytes_to_read = min(n_to_read, pipe_buffer.unread_count)
        for _ in range(no_bytes_to_read):
            read_char = pipe_buffer.buffer[pipe_buffer.read_position]
            pipe_buffer.buffer[pipe_buffer.read_position] = None
            pipe_buffer.read_position = (pipe_buffer.read_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count -= 1
            chars_read.append(read_char)

        print("pipe bytes_read", chars_read)
        print("pipe read is gonna return")
        bytes_read = [ord(b) for b in chars_read]
        return bytes_read

class PipeWriteEnd(OpenFileObject):
    def __init__(self, file_name, file_struct):
        super().__init__(file_name, file_struct)
        self.ref_cnt = 1
        self.referenced_by = []
        self.read_end_ptr = None

    def write(self, bytes_to_write):
        pipe_buffer = self.file_struct
        for i in range(min(pipe_buffer.buffer_size - pipe_buffer.unread_count, len(bytes_to_write))):
            pipe_buffer.buffer[pipe_buffer.write_position] = bytes_to_write[i]
            pipe_buffer.write_position = (pipe_buffer.write_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count += 1
        return ("unblock", Resource("I/O", self))
