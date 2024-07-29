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

    def read(self, bytes_to_read):
        position = 0
        f = self.file_struct
        f.seek(position)
        while bytes_to_read > 0:
            print(bytes_to_read)
            bytes_read = f.read(bytes_to_read)
            if bytes_read == '':
                print("     read blocked! What should happen now?")
                yield ("block", Resource("I/O", self))
            print(bytes_read)
            bytes_to_read -= len(bytes_read)
            position += len(bytes_read)
            f.seek(position)
        return

    def write(self, bytes_to_write):
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


class Pipe(OpenFileObject):
    def __init__(self, file_name, file_struct, mode):
        super().__init__(file_name, file_struct)
        self.mode = mode
        self.ref_cnt = 1
        self.referenced_by = []

        if mode == "rd":
            def read(self, n_to_read):
                array_of_returned_bytes = []
                n_left = n_to_read
                while n_left > 0:
                    pipe_buffer = self.file_struct
                    print("pipe buf: ", f)
                    print(n_left)

                    bytes_read = []
                    chunk_len = min(n_left, self.unread_count)
                    for _ in range(chunk_len):
                        bytes_read.append(pipe_buffer.buffer[pipe_buffer.read_position])
                        pipe_buffer.buffer[pipe_buffer.read_position] = None
                        pipe_buffer.read_position = (pipe_buffer.read_position + 1) % pipe_buffer.buffer_size
                        pipe_buffer.unread_count -= 1
                    array_of_returned_bytes += bytes_read

                    if bytes_read == []:
                        print("     read blocked! What should happen now?")
                        yield ("block", Resource("I/O",open_file_object))
                    print(bytes_read)
                    n_left -= chunk_len
                return array_of_returned_bytes


# class Pipe:
#     def __init__(self):
#         self.buffer_size = 10
#         self.buffer = [None] * self.buffer_size
#         self.write_position = 0
#         self.read_position = 0
#         self.unread_count = 0

#     def read(self, n_to_read):
#         bytes_read = []
#         for _ in range(min(n_to_read, self.unread_count)):
#             bytes_read.append(self.buffer[self.read_position])
#             self.buffer[self.read_position] = None
#             self.read_position = (self.read_position + 1) % self.buffer_size
#             self.unread_count -= 1
#         return bytes_read

#     def write(self, bytes_to_write):
#         for i in range(min(self.buffer_size - self.unread_count, len(bytes_to_write))):
#             self.buffer[self.write_position] = bytes_to_write[i]
#             self.write_position = (self.write_position + 1) % self.buffer_size
#             self.unread_count += 1
