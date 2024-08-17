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

    def read(self, no_bytes_to_read):
        f = self.file_struct
        chars_read = f.read(no_bytes_to_read)
        array_of_bytes_read = [ord(c) for c in chars_read]
        return (array_of_bytes_read, None)

    def write(self, array_of_bytes_to_write):
        f = self.file_struct
        string_to_write = ""
        for i in range(len(array_of_bytes_to_write)):
            string_to_write += chr(array_of_bytes_to_write[i])
        no_bytes_written = self.file_struct.write(string_to_write)
        f.flush()
        return (no_bytes_written, None)


class RegularFile(OpenFileObject):
    def __init__(self, file_name, file_struct):
        super().__init__(file_name, file_struct)
        self.ref_cnt = 1
        self.position = 0

    def read(self, no_bytes_to_read):
        f = self.file_struct
        f.seek(self.position)
        chars_read = f.read(no_bytes_to_read)
        self.position += len(chars_read)
        array_of_bytes_read = [ord(b) for b in chars_read]
        return (array_of_bytes_read, None)

    def write(self, array_of_bytes_to_write):
        position = 0
        f = self.file_struct
        f.seek(position)
        string_to_write = ""
        for i in range(len(array_of_bytes_to_write)):
            string_to_write += chr(array_of_bytes_to_write[i])
        no_bytes_written = self.file_struct.write(string_to_write)
        f.flush()
        return (no_bytes_written, None)

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

    def read(self, no_bytes_to_read):
        pipe_buffer = self.file_struct
        print("pipe buf: ", self.file_struct.buffer)

        while pipe_buffer.unread_count == 0:
            print("     read blocked! What should happen now?")
            yield ("block", Resource("I/O", self.write_end_ptr))

        chars_read = []
        no_bytes_to_read = min(no_bytes_to_read, pipe_buffer.unread_count)
        for _ in range(no_bytes_to_read):
            read_char = pipe_buffer.buffer[pipe_buffer.read_position]
            pipe_buffer.buffer[pipe_buffer.read_position] = None
            pipe_buffer.read_position = (pipe_buffer.read_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count -= 1
            chars_read.append(read_char)

        print("pipe bytes_read", chars_read)
        print("pipe read is gonna return")
        bytes_read = chars_read
        return (bytes_read, ("unblock", Resource("I/O", self)))

class PipeWriteEnd(OpenFileObject):
    def __init__(self, file_name, file_struct):
        super().__init__(file_name, file_struct)
        self.ref_cnt = 1
        self.referenced_by = []
        self.read_end_ptr = None

    def write(self, array_of_bytes_to_write):
        pipe_buffer = self.file_struct

        while pipe_buffer.unread_count == pipe_buffer.buffer_size:
            print("     write blocked!")
            yield ("block", Resource("I/O", self.read_end_ptr))

        no_bytes_to_write = min(pipe_buffer.buffer_size - pipe_buffer.unread_count, len(array_of_bytes_to_write))
        for i in range(no_bytes_to_write):
            pipe_buffer.buffer[pipe_buffer.write_position] = array_of_bytes_to_write[i]
            pipe_buffer.write_position = (pipe_buffer.write_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count += 1
        return (no_bytes_to_write, ("unblock", Resource("I/O", self)))
