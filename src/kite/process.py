from kite.simulators.simulator import CPUContext
import logging


class ProcessImage:
    def __init__(self, cpu_context: CPUContext):
        self.cpu_context = cpu_context
        self.pid = -1
        self.ppid = -1
        self.children = []
        self.fdt = {}
        self.pending_signals = [0]

    def copy_fdt(self, source_process):
        for k,v in source_process.fdt.items():
            self.fdt[k] = v
            if hasattr(v, "ref_cnt"):
                v.ref_cnt += 1


class ProcessTable:
    def __init__(self):
        self.table = {}
        self.max_pid = 0

    def add(self, process: ProcessImage):
        new_pid =  self.max_pid + 1
        self.table[new_pid] = process


class Resource:
    def __init__(self, resource_type, resources_set):
        self.resource_type = resource_type
        self.resource = resources_set


class OpenFileObject():
    def __init__(self, file_name, file_struct):
        self.file_struct = file_struct
        self.file_name = file_name


class TerminalFile(OpenFileObject):

    def read(self, no_bytes_to_read):
        chars_read = self.file_struct.read(no_bytes_to_read)
        array_of_bytes_read = [ord(c) for c in chars_read]
        return (array_of_bytes_read, None)

    def write(self, array_of_bytes_to_write):
        string_to_write = ""
        for i in range(len(array_of_bytes_to_write)):
            string_to_write += chr(array_of_bytes_to_write[i])
        no_bytes_written = self.file_struct.write(string_to_write)
        self.file_struct.flush()
        return (no_bytes_written, None)


class RegularFile(OpenFileObject):
    def __init__(self, file_name, file_struct):
        super().__init__(file_name, file_struct)
        self.ref_cnt = 1
        self.position = 0

    def read(self, no_bytes_to_read):
        self.file_struct.seek(self.position)
        chars_read = self.file_struct.read(no_bytes_to_read)
        self.position += len(chars_read)
        array_of_bytes_read = [ord(b) for b in chars_read]
        return (array_of_bytes_read, None)

    def write(self, array_of_bytes_to_write):
        position = 0
        self.file_struct.seek(position)
        string_to_write = ""
        for i in range(len(array_of_bytes_to_write)):
            string_to_write += chr(array_of_bytes_to_write[i])
        no_bytes_written = self.file_struct.write(string_to_write)
        self.file_struct.flush()
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

        while pipe_buffer.unread_count == 0:
            logging.info(" # " + "       read blocked! What should happen now?")
            yield ("block", Resource("I/O", [self.write_end_ptr]))

        chars_read = []
        no_bytes_to_read = min(no_bytes_to_read, pipe_buffer.unread_count)
        for _ in range(no_bytes_to_read):
            read_char = pipe_buffer.buffer[pipe_buffer.read_position]
            pipe_buffer.buffer[pipe_buffer.read_position] = None
            pipe_buffer.read_position = (pipe_buffer.read_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count -= 1
            chars_read.append(read_char)

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
            logging.info(" # " + "       write blocked!")
            yield ("block", Resource("I/O", [self.read_end_ptr]))

        no_bytes_to_write = min(pipe_buffer.buffer_size - pipe_buffer.unread_count, len(array_of_bytes_to_write))
        for i in range(no_bytes_to_write):
            pipe_buffer.buffer[pipe_buffer.write_position] = array_of_bytes_to_write[i]
            pipe_buffer.write_position = (pipe_buffer.write_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count += 1
        return (no_bytes_to_write, ("unblock", Resource("I/O", self)))
