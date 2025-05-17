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
    def __init__(self, file_name):
        self.file_name = file_name
        self.ref_cnt = 1
    def __repr__(self):
        return f"{self.file_name} ref_cnt={self.ref_cnt}"


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
    def __init__(self, file_name, file_descriptor):
        super().__init__(file_name)
        self.fd = file_descriptor

    def read(self, no_bytes_to_read):
        # TODO: let's not use array of bytes, but just bytes
        chars_read = os.read(self.fd, no_bytes_to_read)
        return (list(chars_read), None)

    def write(self, array_of_bytes_to_write):
        no_bytes_written = os.write(self.fd, bytes(array_of_bytes_to_write))
        return (no_bytes_written, None)

class VirtualFile(OpenFileObject):
    def __init__(self, file_name, data):
        super().__init__(file_name)
        self.data = data
        self.position = 0

    def read(self, no_bytes_to_read):
        # TODO: let's not use array of bytes, but just bytes
        no_bytes_read = min(len(self.data) - self.position, no_bytes_to_read)
        chars_read = self.data[self.position:self.position + no_bytes_read]
        self.position += no_bytes_read
        return (list(chars_read.encode()), None)

    def write(self, array_of_bytes_to_write):
        # TODO: is ignoring a good solution?
        return (len(array_of_bytes_to_write), None)

class PipeBuffer():
    def __init__(self, buffer_size):
        self.buffer_size = buffer_size
        self.buffer = [None] * self.buffer_size
        self.write_position = 0
        self.read_position = 0
        self.unread_count = 0
        self.write_end_closed = False

class PipeReadEnd(OpenFileObject):
    def __init__(self, file_name, buffer):
        super().__init__(file_name)
        self.referenced_by = []
        self.write_end_ptr = None
        self.buffer = buffer

    def read(self, no_bytes_to_read):
        pipe_buffer = self.buffer

        if pipe_buffer.write_end_closed:
            # NOTE: should it be unblocking?
            return ([], ("unblock", Resource("I/O", self)))

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
    def __init__(self, file_name, buffer):
        super().__init__(file_name)
        self.referenced_by = []
        self.read_end_ptr = None
        self.buffer = buffer

    def write(self, array_of_bytes_to_write):
        pipe_buffer = self.buffer

        while pipe_buffer.unread_count == pipe_buffer.buffer_size:
            logging.info(" # " + "       write blocked!")
            yield ("block", Resource("I/O", [self.read_end_ptr]))

        no_bytes_to_write = min(pipe_buffer.buffer_size - pipe_buffer.unread_count, len(array_of_bytes_to_write))
        for i in range(no_bytes_to_write):
            pipe_buffer.buffer[pipe_buffer.write_position] = array_of_bytes_to_write[i]
            pipe_buffer.write_position = (pipe_buffer.write_position + 1) % pipe_buffer.buffer_size
            pipe_buffer.unread_count += 1
        return (no_bytes_to_write, ("unblock", Resource("I/O", self)))
