from kite.cpu_context import CPUContext, VMAreaStruct
from kite.process import Process, ProcessTable, Pipe
from kite.scheduler import Scheduler
from kite.simulator import Simulator

from kite.consts import *
from kite.loading import check_elf, parse_cpu_context_from_file

from pathlib import Path
import inspect
import os
from copy import deepcopy, copy
from time import sleep

from pyrisc.sim.sim import Event, MemEvent

class Kernel:

    def __init__(self, simulator: Simulator, scheduler: Scheduler):
        self.simulator = simulator
        self.process_table = {}
        self.scheduler = scheduler
        #self.vfs

    @classmethod
    def create(cls):
        simulator = Simulator.create()
        scheduler = Scheduler()
        kernel = cls(simulator, scheduler)
        return kernel

    def start(self, init_program: str) -> None:
        init = self.load_process_from_file(init_program)
        init.pid = 1
        self.process_table[1] = init
        init_thread = self.thread(1)
        self.scheduler.enqueue_thread(init_thread)

        while True:
            sleep(1)
            thread = self.scheduler.get_thread()
            print("ready", self.scheduler.ready_queue)
            print("blocked", self.scheduler.blocked_queue)
            if thread is None:
                if len(self.scheduler.blocked_queue) > 0:
                    thread = self.scheduler.blocked_queue[0]
                    self.scheduler.move_to_ready(thread)
                else:
                    print("No more processes!")
                    break

            result = next(thread)
            if result == "blocked":
                self.scheduler.move_to_blocked(thread)
            # self.scheduler.shift_queue()
            print("yielded:", result)

    def add_new_process(self, process: Process):
        new_pid = max(self.process_table.keys()) + 1
        process.pid = new_pid
        self.process_table[new_pid] = process
        return new_pid

    def thread(self, pid):
        process = self.process_table[pid]
        # event loop
        while True:
            print("PID =", pid)
            # process.cpu_context.vm.dump_mem(0x8001ffe0, 8)
            self.simulator.load_context_into_cpu(process.cpu_context)
            cpu_event = self.simulator.run()
            process.cpu_context = self.simulator.read_context_from_cpu()
            yield from self.react_to_event(process, cpu_event)

    def load_process_from_file(self, program_file: str) -> Process:
        cpu_context = parse_cpu_context_from_file(program_file)
        process = Process(cpu_context)
        # self.process_table.add(process) # nadać pid
        return process

    def react_to_event(self, process: Process, event: Event) -> None:
        # event, addr = cpu_event
        event_t = event.type
        print("event: " + EXC_MSG[event_t])
        # Add Interrupt Descriptor Table??
        if event_t == EXC_ECALL:
            yield from self.call_syscall(process)
        elif event_t == EXC_CLOCK:
            # check whether time quantum elapsed
            # some action of scheduler
            yield 0
        # elif event_t == EXC_PAGE_FAULT:
        elif isinstance(event, MemEvent):
            fault_addr = event.fault_addr
            print(" fault_addr:", hex(fault_addr))
            print(" fault_pc:", hex(process.cpu_context.pc.read()))
            if event_t == EXC_PAGE_FAULT_PERMS:
                print(" SIGSEGV")
                raise NotImplementedError
            elif event_t == EXC_PAGE_FAULT_MISS:
                area = process.cpu_context.vm.get_area_by_va(fault_addr)
                if area is not None:
                    process.cpu_context.vm.add_page_containing_addr(fault_addr)
                else:
                    print(" SIGSEGV")
                    raise NotImplementedError
            else:
                raise NotImplementedError
        else:
            raise NotImplementedError
            # break
        return 0

# --------------------------------------------------------------------------
#   syscall implementations
# --------------------------------------------------------------------------

    def call_syscall(self, process: Process):
        syscall_no = process.cpu_context.regs.read(REG_SYSCALL_NUMBER)
        print(" syscall number = " + str(syscall_no))
        if inspect.isgeneratorfunction(syscall_dict[syscall_no]):
            yield from syscall_dict[syscall_no](self, process)
        else:
            return syscall_dict[syscall_no](self, process)

    def exit_syscall(self, process: Process):
        print(" Process exited!")
        self.scheduler.remove_thread()
        yield "process exited"

    def get_string_from_memory(self, process: Process, string_pointer: int):
        d = ""
        virt_mem = process.cpu_context.vm
        c = virt_mem.get_byte(string_pointer)
        while c != 0:
            d += chr(c)
            string_pointer += 1
            c = virt_mem.get_byte(string_pointer)
        return d

    def open_syscall(self, process: Process):
        print(" open invoked!")
        file_name_pointer = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        print(" open file_name:", file_name)
        path = Path(__file__).parents[2] / "binaries" / file_name
        f = open(path, 'a+')
        fd = max(process.fdt.keys()) + 1
        process.fdt[fd] = f
        process.cpu_context.regs.write(REG_RET_VAL1, fd)
        print(process.fdt)

    def read_syscall(self, process: Process):
        print(" read invoked!")
        fd = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        f = process.fdt[fd]
        if isinstance(f, Pipe):
            bytes_to_read = 5
            while bytes_to_read > 0:
                print("pipe buf: ", f.buffer)
                print(bytes_to_read)
                bytes_read = f.read(bytes_to_read)
                if bytes_read == []:
                    print("     read blocked! What should happen now?")
                    yield "blocked"
                print(bytes_read)
                bytes_to_read -= len(bytes_read)
            return

        position = 0
        f.seek(position)
        bytes_to_read = 5
        while bytes_to_read > 0:
            print(bytes_to_read)
            bytes_read = f.read(bytes_to_read)
            if bytes_read == '':
                print("     read blocked! What should happen now?")
                yield "blocked"
            print(bytes_read)
            bytes_to_read -= len(bytes_read)
            position += len(bytes_read)
            f.seek(position)
        return


    def write_syscall(self, process: Process):
        print(" write invoked!")
        # fd = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        fd = 3
        print("fd =", hex(fd))
        f = process.fdt[fd]
        if isinstance(f, Pipe):
            f.write("Hello from")
            print("pipe buf: ", f.buffer)
            return

        position = 0
        f.seek(position)
        f.write("written\n")
        f.flush()

    def pipe_syscall(self, process: Process):
        print(" pipe invoked")
        fds_p = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        print(hex(fds_p))
        read_fd = max(process.fdt.keys()) + 1
        write_fd = max(process.fdt.keys()) + 2
        # r, w = os.pipe()
        pipe = Pipe()
        process.fdt[read_fd] = pipe
        process.fdt[write_fd] = pipe
        print(process.fdt)
        process.cpu_context.vm.copy_into_vm(fds_p, read_fd)
        process.cpu_context.vm.copy_into_vm(fds_p + 4, write_fd)

    def fork_syscall(self, process: Process):
        print(" fork invoked!")
        child_cpu_context = deepcopy(process.cpu_context)
        child = Process(child_cpu_context)
        # child = deepcopy(process)
        for k,v in process.fdt.items():
            child.fdt[k] = v

        child_pid = self.add_new_process(child)
        process.cpu_context.regs.write(REG_RET_VAL1, child_pid)
        child.cpu_context.regs.write(REG_RET_VAL1, 0)
        child_thread = self.thread(child_pid)
        self.scheduler.enqueue_thread(child_thread)


    def execve_syscall(self, process: Process):
        print(" execve invoked!")
        file_name_pointer = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        print(" execve file_name:", file_name)
        path = Path(__file__).parents[2] / "binaries" / file_name
        new_context = parse_cpu_context_from_file(path)
        process.cpu_context = new_context

syscall_dict = {
                0:  Kernel.read_syscall,
                1:  Kernel.write_syscall,
                2:  Kernel.open_syscall,
                22: Kernel.pipe_syscall,
                57: Kernel.fork_syscall,
                59: Kernel.execve_syscall,
                60: Kernel.exit_syscall
                }
