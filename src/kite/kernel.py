from kite.cpu_context import VMAreaStruct, M_READ_WRITE
from kite.process import ProcessImage, ProcessTable, TerminalFile, RegularFile, PipeBuffer, PipeReadEnd, PipeWriteEnd
from kite.scheduler import Scheduler, Resource
from kite.simulators.simulator import Simulator
from kite.signals import Signal, create_signal_context

from kite.consts import *
from kite.loading import check_elf, parse_cpu_context_from_file

from pathlib import Path
import inspect
import os
from sys import stdin, stdout, stderr
from copy import deepcopy, copy
from kite.struct_definitions import UContext, Sigaction, Stat
import struct
import signal

from kite.consts import Event, MemEvent

import logging


class Kernel:

    def __init__(self, simulator: Simulator, scheduler: Scheduler):
        self.simulator = simulator
        self.process_table = {}
        self.scheduler = scheduler
        self.open_files_table = []
        self.actual_process = None
        signal.signal(signal.SIGINT, lambda signum, frame: self.handle_signal(signum, frame))

    def handle_signal(self, _, _frame):
        self.actual_process.pending_signals.set(Signal.SIGINT)

    @classmethod
    def create(cls, simulator: Simulator):
        scheduler = Scheduler()
        kernel = cls(simulator, scheduler)
        return kernel

    def start(self, init_program: str) -> None:
        init_image = self.load_process_image_from_file(init_program)
        init_image.pid = 1
        init_image.fdt = {0: TerminalFile("stdin", stdin),
                          1: TerminalFile("stdout", stdout),
                          2: TerminalFile("stderr", stderr)}
        self.process_table[1] = init_image
        init_process = self.process_routine(1)
        self.scheduler.enqueue_process((init_image.pid, init_process))

        while True:
            process_entry = self.scheduler.get_process_entry()
            logging.info(f"ready {self.scheduler.dump_ready_queue()}")
            logging.info(f"blocked {self.scheduler.dump_blocked_queue()}")
            if process_entry is None:
                ## ultimately if there is noone ready, kernel should exit
                logging.info("No more processes!")
                break

            pid, process_routine = process_entry
            self.actual_process = self.process_table[pid]
            # check pending signals mask
            logging.info(f"scheduling proces with PID {pid}")
            result = next(process_routine)
            if result:
                logging.info(f"process {pid} yielded: {result[0]} {result[1].resource}")
            else:
                logging.info(f"process {pid} yielded")
            self.scheduler.update_processes_states(pid, process_routine, result)

    def add_new_process(self, process: ProcessImage):
        new_pid = max(self.process_table.keys()) + 1
        process.pid = new_pid
        self.process_table[new_pid] = process
        return new_pid

    def process_routine(self, pid):
        process = self.process_table[pid]
        # event loop
        while True:
            # if some signal is pending, handle it
            # TODO: handle ignoring and blocking signals
            pending_sig = process.pending_signals.get_any()

            # TODO: handle also SIGCHLD
            if pending_sig:
                logging.info(f'entering signal handler for {pending_sig}')
                sigaction = process.sigactions[pending_sig.value]
                new_context = create_signal_context(pending_sig, sigaction, process.cpu_context)
                process.cpu_context_stack.append(new_context)
                process.pending_signals.unset(pending_sig)

            self.simulator.load_context_into_cpu(process.cpu_context)
            hardware_event = self.simulator.run()
            process.cpu_context = self.simulator.read_context_from_cpu()
            result = yield from self.react_to_event(process, hardware_event)
            self.scheduler.update_processes_states(pid, self, result)
            logging.info(f"execution result {self.dump_result(result)}")

    def dump_result(self, result):
        if result is None:
            return "None"
        action, resource = result
        return (action, resource.resource)

    def load_process_image_from_file(self, program_file: str) -> ProcessImage:
        cpu_context = self.simulator.get_initial_context()
        parse_cpu_context_from_file(cpu_context, program_file)
        process = ProcessImage(cpu_context)
        return process

    def react_to_event(self, process: ProcessImage, event: Event) -> None:
        event_t = event.type
        result = None
        if event_t == EXC_ECALL:
            result = yield from self.call_syscall(process)
        elif event_t == EXC_CLOCK:
            logging.info(f"event:  {EXC_MSG[event_t]}")
            # check whether time quantum elapsed
            # some action of scheduler
            yield None
        elif isinstance(event, MemEvent):
            logging.info("event: " + EXC_MSG[event_t])
            fault_addr = event.fault_addr
            logging.info(f"       fault_addr: {hex(fault_addr)}")
            logging.info(f"       fault_pc: {hex(process.cpu_context.reg_read(REG_PC))}")
            if event_t == EXC_PAGE_FAULT_PERMS:
                logging.info(" SIGSEGV")
                #process.pending_signals[SIGSEGV] = 1
                raise NotImplementedError
            elif event_t == EXC_PAGE_FAULT_MISS:
                area = process.cpu_context.vm.get_area_by_va(fault_addr)
                if area is not None:
                    process.cpu_context.vm.add_page_containing_addr(fault_addr)
                elif fault_addr == SIGNAL_RETURN_ADDRESS:
                    # it means signal handler returned, restore previous context
                    # TODO: maybe we want to unset pending mask here?
                    process.cpu_context_stack.pop()
                    yield None
                else:
                    logging.info(" SIGSEGV")
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

    def call_syscall(self, process: ProcessImage):
        syscall_no = process.cpu_context.reg_read(REG_SYSCALL_NUMBER)
        logging.info("event: " + EXC_MSG[EXC_ECALL] + " - " + syscall_names[syscall_no])
        if inspect.isgeneratorfunction(syscall_dict[syscall_no]):
            result = yield from syscall_dict[syscall_no](self, process)
        else:
            result = syscall_dict[syscall_no](self, process)
        return result

    def exit_syscall(self, process: ProcessImage):
        logging.info("       Process exited!")
        self.scheduler.remove_process()
        if process.pid == 1:    # I am init
            yield ("unblock", Resource("child state" , process.pid))
        parent = self.process_table[process.ppid]
        parent.pending_signals.set(Signal.SIGCHLD)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)
        yield ("unblock", Resource("child state" , process.pid))

    def get_string_from_memory(self, process: ProcessImage, string_pointer: int):
        d = ""
        virt_mem = process.cpu_context.vm
        c = virt_mem.get_byte(string_pointer)
        while c != 0:
            d += chr(c)
            string_pointer += 1
            c = virt_mem.get_byte(string_pointer)
        return d

    def __modify_sysroot_path(self, path):
        if os.path.isabs(path):
            # Substitute the prefix in the absolute path
            return os.path.join(os.getcwd(), 'sysroot', os.path.relpath(path, os.path.sep))
        return path

    def open_syscall(self, process: ProcessImage):
        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        logging.info(f"       open file_name: {file_name}")
        fd = max(process.fdt.keys()) + 1
        path = Path(__file__).parents[2] / "binaries" / file_name
        f = open(path, 'a+')
        ofo = RegularFile(file_name, f)
        self.open_files_table.append(ofo)
        process.fdt[fd] = ofo
        process.cpu_context.reg_write(REG_RET_VAL1, fd)
        logging.info(f"{process.fdt}")

    def openat_syscall(self, process: ProcessImage):
        AT_FDCWD = -100
        # TODO: implement it properly
        fd = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        if fd != AT_FDCWD:
            raise NotImplementedError("Only AT_FDCWD value for file descriptor is supported")
        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        file_name = self.__modify_sysroot_path(file_name)
        logging.info(f"       open file_name: {file_name}")
        fd = max(process.fdt.keys()) + 1
        path = Path(__file__).parents[2] / "binaries" / file_name
        f = open(path, 'a+')
        ofo = RegularFile(file_name, f)
        self.open_files_table.append(ofo)
        process.fdt[fd] = ofo
        process.cpu_context.reg_write(REG_RET_VAL1, fd)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)
        logging.info(f"{process.fdt}")

    def fstat_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        statbuf_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        # TODO: do we really want to pass all host values?

        # Is file stdin, stdout or stderr?
        if 0 <= fd <= 2:
            stat_info = os.fstat(fd)
        else:
            file_path = process.fdt[fd].file_name
            stat_info = os.stat(file_path)

        stat_bytes = Stat.pack(stat_info)
        process.cpu_context.vm.copy_bytes_in_vm(statbuf_ptr, stat_bytes)

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def dup_syscall(self, process: ProcessImage):
        oldfd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        newfd = max(process.fdt.keys()) + 1
        process.fdt[newfd] = process.fdt[oldfd]
        process.cpu_context.reg_write(REG_RET_VAL1, newfd)

    def sigaltstack_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def sigprocmask_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def setcontext_syscall(self, process: ProcessImage):
        # Currently only general purpose registers are updated
        # TODO: Add support for other fields of ucontext_t
        statbuf_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        regs_to_update = [
                REG_RV,
                REG_RA,
                REG_SP,
                REG_GP,
                REG_TP,
                REG_S0,
                REG_S1,
                REG_S2,
                REG_S3,
                REG_S4,
                REG_S5,
                REG_S6,
                REG_S7,
                REG_S8,
                REG_S9,
                REG_S10,
                REG_S11,
                REG_PC,
        ]

        data = process.cpu_context.vm.load_bytes_from_vm(statbuf_ptr, UContext.SIZE)
        reg_values = UContext.unpack(bytes(data))["gregs"]

        for reg in regs_to_update:
            process.cpu_context.reg_write(reg, reg_values[reg])

    def ioctl_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def close_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        del process.fdt[fd]
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def sbrk_syscall(self, process: ProcessImage):
        increment = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        brk = process.cpu_context.vm.brk
        process.cpu_context.reg_write(REG_RET_VAL1, brk)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

        if increment < 0:
            raise NotImplementedError("brk: negative increment is not supported")
        if increment == 0:
            return

        vm_areas_list = process.cpu_context.vm.vm_areas_list
        for area in vm_areas_list:
            area_offset_start = area.start_vpn << VPO_LENTGH
            area_offset_end = area_offset_start + (area.page_cnt << VPO_LENTGH)

            if area_offset_end == brk:
                vm_areas_list.add(VMAreaStruct(brk, increment, M_READ_WRITE, 0, bytes(increment)))
                break

        process.cpu_context.vm.brk += increment
        logging.info(f'old brk = 0x{brk:x}, new brk = 0x{process.cpu_context.vm.brk}')

    def sigaction_syscall(self, process: ProcessImage):
        signal_number = INT(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        new_action_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        # TODO: handle old action

        try:
            signal = Signal(signal_number)
        except ValueError:
            # TODO: handle it with errno and proper return value
            raise NotImplementedError("Incorrect signal number")

        supported_signals = [Signal.SIGCHLD, Signal.SIGINT]
        if signal not in supported_signals:
            raise NotImplementedError(f'Unsupported syscall number: {signal}, only {supported_signals} are supported')

        data = process.cpu_context.vm.load_bytes_from_vm(new_action_pointer, Sigaction.SIZE)
        new_action = Sigaction.unpack(bytes(data))
        process.sigactions[signal.value] = new_action

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def mmap_syscall(self, process: ProcessImage):
        size = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        # Find free space
        # in [MMAP_SEGMENTS_RANGE_START, MMAP_SEGMENTS_RANGE_END]
        vm_areas_list = process.cpu_context.vm.vm_areas_list
        prev_addr = 0
        addr = -1
        for area in vm_areas_list:
            area_offset_start = area.start_vpn << VPO_LENTGH
            area_offset_end = area_offset_start + (area.page_cnt << VPO_LENTGH)

            if prev_addr > MMAP_SEGMENTS_RANGE_END:
                break

            prev_addr = max(prev_addr, MMAP_SEGMENTS_RANGE_START)
            if min(area_offset_start, MMAP_SEGMENTS_RANGE_END) - prev_addr > size:
                addr = prev_addr
                break
            prev_addr = area_offset_end

        if addr == -1:
            raise NotImplementedError("mmap: no more space")

        vm_areas_list.add(VMAreaStruct(addr, size, M_READ_WRITE, 0, bytes(size)))

        process.cpu_context.reg_write(REG_RET_VAL1, addr)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def issetugid_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 1)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def readlinkat_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL2, -1)

    def read_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        buff_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        count = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        open_file_object = process.fdt[fd]
        read_method = open_file_object.read
        if inspect.isgeneratorfunction(read_method):
            read_result = yield from read_method(count)
        else:
            read_result = read_method(count)

        array_of_bytes_read, result = read_result
        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(buff_ptr, array_of_bytes_read)
        bytes_read = len(array_of_bytes_read)
        process.cpu_context.reg_write(REG_RET_VAL1, bytes_read)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)
        return result


    def write_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        buff_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        count = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        open_file_object = process.fdt[fd]
        f = open_file_object.file_struct
        array_of_bytes_to_write = process.cpu_context.vm.load_bytes_from_vm(buff_ptr, count)

        write_method = open_file_object.write
        if inspect.isgeneratorfunction(write_method):
            write_result = yield from write_method(array_of_bytes_to_write)
        else:
            write_result = write_method(array_of_bytes_to_write)

        no_bytes_written, result = write_result
        process.cpu_context.reg_write(REG_RET_VAL1, no_bytes_written)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)
        return result

    def pipe_syscall(self, process: ProcessImage):
        fds_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        read_fd = max(process.fdt.keys()) + 1
        write_fd = max(process.fdt.keys()) + 2

        buffer = PipeBuffer(10)
        read_ofo = PipeReadEnd("pipe_" + str(process.pid) + "_rd", buffer)
        write_ofo = PipeWriteEnd("pipe_" + str(process.pid) + "_wr", buffer)
        read_ofo.write_end_ptr = write_ofo
        write_ofo.read_end_ptr = read_ofo
        self.open_files_table.append(read_ofo)
        self.open_files_table.append(write_ofo)
        process.fdt[read_fd] = read_ofo
        process.fdt[write_fd] = write_ofo

        process.cpu_context.vm.copy_byte_in_vm(fds_ptr, read_fd)
        process.cpu_context.vm.copy_byte_in_vm(fds_ptr + INT_SIZE, write_fd)

    def clock_gettime_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        timespec_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        process.cpu_context.vm.copy_bytes_in_vm(timespec_ptr, bytes(16))
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def fork_syscall(self, process: ProcessImage):
        child_cpu_context = deepcopy(process.cpu_context)
        child = ProcessImage(child_cpu_context)
        child.copy_fdt(process)
        child_pid = self.add_new_process(child)
        child.ppid = process.pid
        process.children.append(child)

        process.cpu_context.reg_write(REG_RET_VAL1, child_pid)
        child.cpu_context.reg_write(REG_RET_VAL1, 0)
        child_process = self.process_routine(child_pid)
        self.scheduler.enqueue_process((child_pid, child_process))


    def execve_syscall(self, process: ProcessImage):
        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        logging.info(f" execve file_name: {file_name}")
        path = Path(__file__).parents[2] / "binaries" / file_name
        cpu_context = self.simulator.get_initial_context()
        parse_cpu_context_from_file(cpu_context, path)
        process.cpu_context = cpu_context

    def debug_print(self, process: ProcessImage):
        value = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        logging.info(f"{hex(value)}")

    def wait_syscall(self, process: ProcessImage):
        while True:
            if process.pending_signals.is_set(Signal.SIGCHLD):
                logging.info(" My child terminated!")
                process.pending_signals.unset(Signal.SIGCHLD)
                return
            else:
                yield ("block", Resource("child state", [child.pid for child in process.children]))


syscall_dict = {
                1: Kernel.exit_syscall,
                2:  Kernel.open_syscall,
                3:  Kernel.read_syscall,
                4:  Kernel.write_syscall,
                5:  Kernel.openat_syscall,
                6:  Kernel.close_syscall,
                11: Kernel.fstat_syscall,
                12: Kernel.sbrk_syscall,
                13: Kernel.mmap_syscall,
                18: Kernel.sigaction_syscall,
                22: Kernel.pipe_syscall,
                26: Kernel.clock_gettime_syscall,
                32: Kernel.dup_syscall,
                37: Kernel.sigaltstack_syscall,
                38: Kernel.sigprocmask_syscall,
                39: Kernel.setcontext_syscall,
                40: Kernel.ioctl_syscall,
                45: Kernel.issetugid_syscall,
                49: Kernel.readlinkat_syscall,
                57: Kernel.fork_syscall,
                59: Kernel.execve_syscall,
                100: Kernel.debug_print,
                247: Kernel.wait_syscall
                }
