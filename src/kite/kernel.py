from kite.cpu_context import VMAreaStruct, M_READ_WRITE
from kite.process import ProcessImage, TerminalFile, RegularFile, PipeBuffer, PipeReadEnd, PipeWriteEnd
from kite.scheduler import Scheduler, Resource
from kite.simulators.simulator import Simulator
from kite.signals import Signal, create_signal_context, SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK, SIG_DFL, SIG_IGN, default_action, DefaultAction, STATUS_EXITED, STATUS_SIGNALED, STATUS_STOPPED

from kite.consts import *
from kite.loading import check_elf, parse_cpu_context_from_file
from kite.procstat import procstat_creator

from pathlib import Path
import inspect
import os
from copy import deepcopy
from kite.struct_definitions import UContext, Sigaction, Stat, Termios, Dirent, convert_o_flags_netbsd_to_linux
import signal
import sys
import termios
from getdents import *

from kite.consts import Event, MemEvent

import logging


class Kernel:

    def __init__(self, simulator: Simulator, scheduler: Scheduler):
        self.simulator = simulator
        self.process_table = {}
        self.scheduler = scheduler
        self.open_files_table = []

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
            # check signals mask
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
        parent.pending_signals[0] = 1
        yield ("unblock", Resource("child state" , process.pid))

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

    def dup_syscall(self, process: ProcessImage):
        oldfd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        newfd = max(process.fdt.keys()) + 1
        process.fdt[newfd] = process.fdt[oldfd]
        process.cpu_context.reg_write(REG_RET_VAL1, newfd)

    def close_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        del process.fdt[fd]
    def kill_syscall(self, process: ProcessImage):
        pid = INT(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        signal = INT(process.cpu_context.reg_read(REG_SYSCALL_ARG1))

        if pid > 0:
            self.process_table[pid].signal_set.set_pending(Signal(signal))
        elif pid < 0 and pid != -1:
            pgid = -pid
            for target_process in self.process_table.values():
                if target_process.pgid == pgid:
                    target_process.signal_set.set_pending(Signal(signal))
        else:
            raise NotImplementedError(f"kill: {pid} pid is not implemented")

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def sbrk_syscall(self, process: ProcessImage):
        increment = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        brk = process.cpu_context.vm.brk
        process.cpu_context.reg_write(REG_RET_VAL1, brk)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

        if brk + increment > MMAP_SEGMENTS_RANGE_START:
            raise NotImplementedError("brk: no free memory left")

        if increment < 0:
            raise NotImplementedError("brk: negative increment is not supported")
        if increment == 0:
            return

        vm_areas_list = process.cpu_context.vm.vm_areas_list
        vm_areas_list.add(VMAreaStruct(brk, increment, M_READ_WRITE, 0, bytearray(increment)))

        process.cpu_context.vm.brk += increment
        logging.info(f'old brk = 0x{brk:x}, new brk = 0x{process.cpu_context.vm.brk:x}')

    def sigaction_syscall(self, process: ProcessImage):
        signal_number = INT(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        new_action_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        # TODO: handle old action

        try:
            signal = Signal(signal_number)
        except ValueError:
            # TODO: handle it with errno and proper return value
            raise NotImplementedError("Incorrect signal number")

        data = process.cpu_context.vm.load_bytes_from_vm_as_kernel(new_action_pointer, Sigaction.SIZE)
        new_action = Sigaction.unpack(bytes(data))
        process.sigactions[signal.value] = new_action

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def wait4_syscall(self, process: ProcessImage):
        pid = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        status_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        options = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
        rusage = process.cpu_context.reg_read(REG_SYSCALL_ARG3)

        if rusage != 0:
            raise NotImplementedError("wait4: rusage: Currently only NULL value is supported")

        if options != WNOHANG | WUNTRACED:
            raise NotImplementedError("wait4: options: Currently only WNOHANG|WUNTRACED value is supported")

        if pid != -1:
            raise NotImplementedError("wait4: pid: Currently only -1 value is supported")
        
        ret_val = 0
        status = 0
        if len(process.zombies) > 0:
            zombie_process, status = process.zombies.pop()
            ret_val = zombie_process.pid
        # No zombies? Check for stopped processes
        elif len(self.scheduler.unreported_stopped_processes) > 0:
            stopped_process = self.scheduler.unreported_stopped_processes.pop()
            self.scheduler.reported_stopped_processes.append(stopped_process)
            ret_val = stopped_process.pid
            # currently we support only SIGTSTP for stopping
            status = STATUS_STOPPED(Signal.SIGTSTP)

        process.cpu_context.vm.write_int(status_ptr, status)
        process.cpu_context.reg_write(REG_RET_VAL1, ret_val)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)


    def mmap_syscall(self, process: ProcessImage):
        # TODO: at list throw for not supported flags
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

        vm_areas_list.add(VMAreaStruct(addr, size, M_READ_WRITE, 0, bytearray(size)))

        process.cpu_context.reg_write(REG_RET_VAL1, addr)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def getdents_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        buff_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        nbytes = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        fd = process.fdt[fd].fd

        res = bytes()
        for inode, type, name in getdents_raw(fd, nbytes):
            res += Dirent.pack(inode, type, name)

        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(buff_ptr, res)

        process.cpu_context.reg_write(REG_RET_VAL1, len(res))
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def sigsuspend_syscall(self, process: ProcessImage):
        # TODO: implement mask
        logging.info("Started waiting for the signal")
        while True:
            if process.signal_received != -1:
                process.signal_received = -1
                logging.info("Received signal during wait")
                process.cpu_context.reg_write(REG_RET_VAL1, 0)
                process.cpu_context.reg_write(REG_RET_VAL2, 0)
                return
            else:
                yield ("block", Resource("signal", [child.pid for child in process.children]))

    def fcntl_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        cmd = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        # TODO: actually implement F_GETFL and F_SETFL
        supported_commands = [F_DUPFD, F_SETFD, F_GETFL]

        if cmd not in supported_commands:
            raise NotImplementedError(f"cmd {cmd} is not supported")

        base = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        ret_val = 0
        if cmd == F_DUPFD:
            newfd = max(max(process.fdt.keys()) + 1, base)
            process.fdt[newfd] = process.fdt[fd]
            process.fdt[newfd].ref_cnt += 1
            ret_val = newfd
            if LOG_FD_CHANGES:
                logging.info(process.fdt)
        process.cpu_context.reg_write(REG_RET_VAL1, ret_val)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

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
        array_of_bytes_to_write = process.cpu_context.vm.load_bytes_from_vm_as_kernel(buff_ptr, count)

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
        if LOG_FD_CHANGES:
            logging.info(process.fdt)

        process.cpu_context.vm.write_int(fds_ptr, int(read_fd))
        process.cpu_context.vm.write_int(fds_ptr + INT_SIZE, int(write_fd))

    def pipe2_syscall(self, process: ProcessImage):
        # TODO: handle flags
        self.pipe_syscall(process)

    def fstatat_syscall(self, process: ProcessImage):
        # TODO: add handling CWD
        fd = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        if fd != AT_FDCWD:
            raise NotImplementedError("Only AT_FDCWD value for file descriptor is supported")

        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        path = process.cpu_context.vm.read_string(file_name_pointer)
        path = self.__modify_sysroot_path(path)

        return_val = -1
        if path and os.path.isfile(path) or os.path.isdir(path):
            return_val = 0

            # TODO: do we really want to pass all host values?
            stat_info = os.stat(path)
            stat_bytes = Stat.pack(stat_info)
            statbuf_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
            process.cpu_context.vm.copy_bytes_in_vm_as_kernel(statbuf_ptr, stat_bytes)

        process.cpu_context.reg_write(REG_RET_VAL1, return_val)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def setpgid_syscall(self, process: ProcessImage):
        pid = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        pgrp = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        if pid == 0:
            process.pgid = pgrp
        else:
            self.process_table[pid].pgid = pgrp

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def chdir_syscall(self, process: ProcessImage):
        path_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        path = process.cpu_context.vm.read_string(path_ptr)

        host_path = self.__modify_sysroot_path(path)
        ret = -1
        if host_path and os.path.exists(host_path):
            ret = 0
            self.cwd = host_path

        process.cpu_context.reg_write(REG_RET_VAL1, ret)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def fork_syscall(self, process: ProcessImage):
        # TODO: do we want to copy whole context stack?
        child_cpu_context = deepcopy(process.cpu_context)
        child_pid = self.get_pid()
        child = ProcessImage(child_pid, child_cpu_context, self.process_routine(child_pid))
        child.copy_fdt(process)
        if LOG_FD_CHANGES:
            logging.info(process.fdt)
        self.process_table[child_pid] = child
        child.ppid = process.pid
        child.pgid = process.pgid
        child.signal_set = deepcopy(process.signal_set)
        child.sigactions = deepcopy(process.sigactions)
        process.children.append(child)

        process.cpu_context.reg_write(REG_RET_VAL1, child_pid)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)
        child.cpu_context.reg_write(REG_RET_VAL1, 0)
        child.cpu_context.reg_write(REG_RET_VAL2, 0)
        self.scheduler.enqueue_process(child)


    def execve_syscall(self, process: ProcessImage):
        # TODO: handle close on exec
        kernel_path_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        kernel_path = process.cpu_context.vm.read_string(kernel_path_pointer)
        argv_addr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        envp_addr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
        argv = process.cpu_context.vm.read_string_list(argv_addr)
        env = process.cpu_context.vm.read_string_list(envp_addr)
        cpu_context = self.simulator.get_initial_context()
        host_path = self.__modify_sysroot_path(kernel_path)
        if not host_path:
            raise NotImplementedError(f"execve: path {host_path} doesn't exist")

        # the file might be binary script
        with open(host_path, 'rb') as f:
            first_bytes = f.read(2)
            if first_bytes == b'#!':
                interpreter_line = f.readline().decode('utf-8').strip()
                # TODO: what about other arguments?
                interpreter = interpreter_line.split()
                host_path = self.__modify_sysroot_path(interpreter[0])
                # when running shell script, first argument should be interpreter,
                # second should be replaced with actual file name (e.g. /bin/ps instead of ps)
                argv = interpreter + [kernel_path] + argv[1:]

        logging.info(f" execve file_name: {kernel_path}")
        logging.info(f" on host it is file: {host_path}")
        parse_cpu_context_from_file(cpu_context, host_path, argv, env)
        process.cpu_context = cpu_context
        process.command = " ".join(argv)

    def sigtimedwait_syscall(self, process: ProcessImage):
        # TODO: implement mask, siginfo and timeout
        logging.info("Started waiting for the signal")
        while True:
            if process.signal_received != -1:
                logging.info("Received signal during wait")
                process.cpu_context.reg_write(REG_RET_VAL1, process.signal_received)
                process.cpu_context.reg_write(REG_RET_VAL2, 0)
                process.signal_received = -1
                return
            else:
                yield ("block", Resource("signal", [child.pid for child in process.children]))

syscall_dict = {
                2:  Kernel.open_syscall,
                32: Kernel.dup_syscall,
                1: Kernel.exit_syscall,
                2:  Kernel.fork_syscall,
                3:  Kernel.read_syscall,
                4:  Kernel.write_syscall,
                10: Kernel.kill_syscall,
                12: Kernel.sbrk_syscall,
                13: Kernel.mmap_syscall,
                15: Kernel.getdents_syscall,
                18: Kernel.sigaction_syscall,
                20: Kernel.wait4_syscall,
                24: Kernel.fstatat_syscall,
                25: Kernel.pipe2_syscall,
                28: Kernel.execve_syscall,
                30: Kernel.setpgid_syscall,
                35: Kernel.chdir_syscall,
                46: Kernel.fcntl_syscall,
                55: Kernel.sigsuspend_syscall,
                86: Kernel.sigtimedwait_syscall,
                }
