from kite.simulators.simulator import CPUContext
import logging
from kite.signals import Signal, SignalSet, SIGNAL_NUM, SIG_DFL
import sys
from sys import stdout
import os
import select

class ProcessImage:
    def __init__(self, pid, cpu_context: CPUContext, process_routine):
        # process context and all signal contexts
        self.subroutine_stack = [[cpu_context, process_routine]]
        self.pid = pid
        self.ppid = 0
        self.pgid = 1
        self.children = []
        self.fdt = {}
        self.signal_set = SignalSet()
        self.sigactions = [{"handler": SIG_DFL}] * SIGNAL_NUM
        self.zombies = []
        self.signal_received = -1
        self.command = ""

    @property
    def process_routine(self):
        return self.subroutine_stack[-1][1]

    @process_routine.setter
    def process_routine(self, process_routine):
        self.subroutine_stack[-1][1] = process_routine

    @property
    def cpu_context(self):
        return self.subroutine_stack[-1][0]

    @cpu_context.setter
    def cpu_context(self, context):
        self.subroutine_stack[-1][0] = context

    def push_subroutine(self, cpu_context, process_routine):
        self.subroutine_stack.append([cpu_context, process_routine])

    def pop_subroutine(self):
        self.subroutine_stack.pop()

    def copy_fdt(self, source_process):
        for k,v in source_process.fdt.items():
            self.fdt[k] = v
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

SIGINT_CHAR = '\x03'
SIGTSTP_CHAR = '\x1A'
ESCAPE_CHAR = '\x1b'

class TerminalFile(OpenFileObject):
    def __init__(self, file_name):
        super().__init__(file_name)
        self.in_canonical_mode = True
        self.echo_flag = True
        self.isig_flag = True
        self.buffer = []

    def __is_end_character_of_escape_sequence(self, c):
        return c in ['m', 'A', 'B', 'C', 'D', 'H', 'f', '~', 'R', 'Z', 's', 'u', 'J', 'K', 'L', 'M', 'P', 'X', '@', '|', '!']

    def handle_host_input(self, handle_signal):
        rlist, _, _ = select.select([sys.stdin], [], [], 0.0)
        if rlist:
            char = sys.stdin.read(1)
            if self.isig_flag and char == SIGINT_CHAR:
                handle_signal(Signal.SIGINT)
            elif self.isig_flag and char == SIGTSTP_CHAR:
                handle_signal(Signal.SIGTSTP)
            else:
                self.buffer += char
                if self.echo_flag:
                    sys.stdout.write(char)
                # for some reason select won't notify us for remaining escape characters
                if char == ESCAPE_CHAR:
                    while True:
                        char = sys.stdin.read(1)
                        self.buffer += char
                        if self.__is_end_character_of_escape_sequence(char):
                            break

    def read(self, no_bytes_to_read):
        while True:
            if len(self.buffer) >= no_bytes_to_read or (self.in_canonical_mode and len(self.buffer) > 0 and self.buffer[-1] == '\n'):
                chars_number = min(len(self.buffer), no_bytes_to_read)
                array_of_bytes_read = [ord(c) for c in self.buffer[:chars_number]]
                self.buffer = self.buffer[chars_number:]
                return (array_of_bytes_read, None)
            else:
                yield ("block", Resource("stdin", [self]))

    def write(self, array_of_bytes_to_write):
        string_to_write = ""
        for i in range(len(array_of_bytes_to_write)):
            string_to_write += chr(array_of_bytes_to_write[i])
        no_bytes_written = stdout.write(string_to_write)
        stdout.flush()
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
