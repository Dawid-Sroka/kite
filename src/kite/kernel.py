from kite.cpu_context import CPUContext, VMAreaStruct
from kite.process import Process, ProcessTable, OpenFileObject, RegularFile, PipeBuffer, PipeReadEnd, PipeWriteEnd
from kite.scheduler import Scheduler, Resource
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
        self.open_files_table = {}

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
        self.scheduler.enqueue_thread((init.pid, init_thread))

        while True:
            # sleep(1)
            thread_object = self.scheduler.get_thread()
            print("ready", self.scheduler.ready_queue)
            print("blocked", self.scheduler.blocked_queue)
            if thread_object is None:
                ## ultimately if there is noone ready, kernel should exit
                print("No more processes!")
                break

            pid, thread = thread_object
            # check pending signals mask
            result = next(thread)
            print("yielded:", result[0], result[1].resource)
            self.scheduler.update_processes_states(pid, thread, result)
            # self.scheduler.shift_queue()

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
            hardware_event = self.simulator.run()
            process.cpu_context = self.simulator.read_context_from_cpu()
            result = yield from self.react_to_event(process, hardware_event)
            self.scheduler.update_processes_states(pid, self, result)
            print("result", result)

    def load_process_from_file(self, program_file: str) -> Process:
        cpu_context = parse_cpu_context_from_file(program_file)
        process = Process(cpu_context)
        return process

    def react_to_event(self, process: Process, event: Event) -> None:
        # event, addr = cpu_event
        event_t = event.type
        print("event: " + EXC_MSG[event_t])
        result = None
        # Add Interrupt Descriptor Table??
        if event_t == EXC_ECALL:
            result = yield from self.call_syscall(process)
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
        return result

# --------------------------------------------------------------------------
#   syscall implementations
# --------------------------------------------------------------------------

    def call_syscall(self, process: Process):
        syscall_no = process.cpu_context.regs.read(REG_SYSCALL_NUMBER)
        print(" syscall number = " + str(syscall_no))
        if inspect.isgeneratorfunction(syscall_dict[syscall_no]):
            result = yield from syscall_dict[syscall_no](self, process)
        else:
            result = syscall_dict[syscall_no](self, process)
        return result

    def exit_syscall(self, process: Process):
        print(" Process exited!")
        self.scheduler.remove_thread()
        if process.pid == 1:    # I am init
            yield ("unblock", Resource("child state" , process.pid))
        parent = self.process_table[process.ppid]
        parent.pending_signals[0] = 1
        # self.scheduler.notify_all_waiting_for_event()
        yield ("unblock", Resource("child state" , process.pid))

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
        fd = max(process.fdt.keys()) + 1
        if file_name in self.open_files_table.keys():
            process.fdt[fd] = self.open_files_table[file_name]
            self.open_files_table[file_name].ref_cnt += 1
        else:
            path = Path(__file__).parents[2] / "binaries" / file_name
            f = open(path, 'a+')
            ofo = RegularFile(file_name, f)
            self.open_files_table[file_name] = ofo
            process.fdt[fd] = ofo
        process.cpu_context.regs.write(REG_RET_VAL1, fd)
        print(process.fdt)

    def read_syscall(self, process: Process):
        print(" read invoked!")
        fd = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        buff_ptr = process.cpu_context.regs.read(REG_SYSCALL_ARG1)
        count = process.cpu_context.regs.read(REG_SYSCALL_ARG2)

        open_file_object = process.fdt[fd]
        read_method = open_file_object.read
        if inspect.isgeneratorfunction(read_method):
            read_result = yield from read_method(count)
        else:
            read_result = read_method(count)

        array_of_bytes_read, result = read_result
        process.cpu_context.vm.copy_bytes_in_vm(buff_ptr, array_of_bytes_read)
        bytes_read = len(array_of_bytes_read)
        process.cpu_context.regs.write(REG_RET_VAL1, bytes_read)


    def write_syscall(self, process: Process):
        print(" write invoked!")
        fd = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        buff_ptr = process.cpu_context.regs.read(REG_SYSCALL_ARG1)
        count = process.cpu_context.regs.read(REG_SYSCALL_ARG2)

        open_file_object = process.fdt[fd]
        f = open_file_object.file_struct
        array_of_bytes_to_write = process.cpu_context.vm.load_bytes_from_vm(buff_ptr, count)

        write_method = open_file_object.write
        if inspect.isgeneratorfunction(write_method):
            write_result = yield from write_method(array_of_bytes_to_write)
        else:
            write_result = write_method(array_of_bytes_to_write)

        no_bytes_written, result = write_result
        process.cpu_context.regs.write(REG_RET_VAL1, no_bytes_written)
        process.cpu_context.vm.dump_mem_in_bytes(buff_ptr, 8)
        return result

    def pipe_syscall(self, process: Process):
        print(" pipe invoked")
        fds_ptr = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        read_fd = max(process.fdt.keys()) + 1
        write_fd = max(process.fdt.keys()) + 2

        buffer = PipeBuffer(10)
        read_ofo = PipeReadEnd("pipe_" + str(process.pid) + "_rd", buffer)
        write_ofo = PipeWriteEnd("pipe_" + str(process.pid) + "_wr", buffer)
        read_ofo.write_end_ptr = write_ofo
        write_ofo.read_end_ptr = read_ofo
        self.open_files_table["pipe_" + str(process.pid) + "_rd"] = read_ofo
        self.open_files_table["pipe_" + str(process.pid) + "_wr"] = write_ofo
        process.fdt[read_fd] = read_ofo
        process.fdt[write_fd] = write_ofo

        process.cpu_context.vm.copy_byte_in_vm(fds_ptr, read_fd)
        process.cpu_context.vm.copy_byte_in_vm(fds_ptr + INT_SIZE, write_fd)

    def fork_syscall(self, process: Process):
        print(" fork invoked!")
        child_cpu_context = deepcopy(process.cpu_context)
        child = Process(child_cpu_context)
        # child = deepcopy(process)
        for k,v in process.fdt.items():
            child.fdt[k] = v

        child_pid = self.add_new_process(child)
        child.ppid = process.pid
        process.cpu_context.regs.write(REG_RET_VAL1, child_pid)
        child.cpu_context.regs.write(REG_RET_VAL1, 0)
        child_thread = self.thread(child_pid)
        self.scheduler.enqueue_thread((child_pid, child_thread))


    def execve_syscall(self, process: Process):
        print(" execve invoked!")
        file_name_pointer = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        print(" execve file_name:", file_name)
        path = Path(__file__).parents[2] / "binaries" / file_name
        new_context = parse_cpu_context_from_file(path)
        process.cpu_context = new_context

    def debug_print(self, process: Process):
        value = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        print(hex(value))
        # process.cpu_context.vm.dump_mem(ptr, 1)

    def wait_syscall(self, process: Process):
        print(" wait invoked!")
        while True:
            if process.pending_signals[0] == 1:
                print(" My child terminated!")
                process.pending_signals[0] == 0
                return
            else:
                yield "blocked"


syscall_dict = {
                0:  Kernel.read_syscall,
                1:  Kernel.write_syscall,
                2:  Kernel.open_syscall,
                22: Kernel.pipe_syscall,
                57: Kernel.fork_syscall,
                59: Kernel.execve_syscall,
                60: Kernel.exit_syscall,
                100: Kernel.debug_print,
                247: Kernel.wait_syscall
                }
