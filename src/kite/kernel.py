from kite.cpu_context import VMAreaStruct, M_READ_WRITE
from kite.process import ProcessImage, ProcessTable, TerminalFile, RegularFile, PipeBuffer, PipeReadEnd, PipeWriteEnd, VirtualFile
from kite.scheduler import Scheduler, Resource
from kite.simulators.simulator import Simulator
from kite.signals import Signal, create_signal_context, SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK, SIG_DFL, SIG_IGN, default_action, DefaultAction, STATUS_EXITED, STATUS_SIGNALED, STATUS_STOPPED

from kite.consts import *
from kite.loading import check_elf, parse_cpu_context_from_file

from kite.log_defs import *

from pathlib import Path
import inspect
import os
from copy import deepcopy, copy
from kite.struct_definitions import UContext, Sigaction, Stat, Termios, convert_o_flags_netbsd_to_linux
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
        self.foreground_process_group = 1
        signal.signal(signal.SIGTERM, lambda signum, frame: self.restore_terminal_settings(signum, frame))
        self.terminal = None

        # In some cases (e.g. running on GH actions) accessing terminal
        # settings is not allowed. In such case don't call tcgetattr/tcsetattr
        try:
            self.initial_term_settings = termios.tcgetattr(sys.stdin)
        except:
            self.initial_term_settings = None

        # We handle ICANON by ourselves
        if self.initial_term_settings:
            attrs_to_update = deepcopy(self.initial_term_settings)
            attrs_to_update[3] &= ~termios.ICANON
            attrs_to_update[3] &= ~termios.ISIG
            attrs_to_update[3] &= ~termios.ECHO
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, attrs_to_update)

        sys.excepthook = self.handle_exception
        self.current_process = None
        self.sysroot = Path(os.getcwd(), 'sysroot')
        self.cwd = self.sysroot

    def restore_terminal_settings(self, _, frame):
        if self.initial_term_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.initial_term_settings)
        sys.exit(0)

    def handle_exception(self, exc_type, exc_value, exc_traceback):
        if self.initial_term_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.initial_term_settings)
        
        # Call the default excepthook to ensure normal failure behavior
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    def handle_signal(self, signal):
        if not self.foreground_process_group:
            return
        for process in self.process_table.values():
            if process.pgid == self.foreground_process_group:
                process.signal_set.set_pending(signal)

    @classmethod
    def create(cls, simulator: Simulator):
        scheduler = Scheduler()
        kernel = cls(simulator, scheduler)
        return kernel

    def start(self, arguments) -> None:
        init_image = self.load_process_image_from_file(1, arguments[0], arguments)
        self.terminal = TerminalFile("/dev/uart")
        init_image.fdt = {0: self.terminal,
                          1: self.terminal,
                          2: self.terminal}
        self.process_table[1] = init_image
        self.scheduler.enqueue_process(init_image)

        while True:
            self.terminal.handle_host_input(lambda x: self.handle_signal(x))
            self.scheduler.reasume_continued_processes()

            process_entry = self.scheduler.get_process_entry()
            self.current_process = process_entry
            logging.info(f"ready {self.scheduler.dump_ready_queue()}")
            logging.info(f"blocked {self.scheduler.dump_blocked_queue()}")
            if process_entry is None:
                ## ultimately if there is noone ready, kernel should exit
                logging.info("No more processes!")
                break

            pid = process_entry.pid

            # if some signal is pending, handle it
            # TODO: handle ignoring and blocking signals
            pending_sig = process_entry.signal_set.get_any()

            # TODO: handle also SIGCHLD
            if pending_sig:
                process_entry.signal_set.unset_pending(pending_sig)
                logging.info(f'entering signal handler for {pending_sig}')
                sigaction = process_entry.sigactions[pending_sig.value]
                if sigaction["handler"] == SIG_IGN:
                    pass
                elif sigaction["handler"] == SIG_DFL:
                    action = default_action[pending_sig]
                    if action == DefaultAction.Term:
                        self.__exit(process_entry, STATUS_SIGNALED(pending_sig))
                        self.scheduler.update_processes_states(None, None)
                        continue
                    elif action == DefaultAction.Stop:
                        self.scheduler.stop_process()
                        parent = self.process_table[process_entry.ppid]
                        # TODO: do that only WUNTRACED
                        parent.signal_set.set_pending(Signal.SIGCHLD)
                        self.scheduler.update_processes_states(None, None)
                        continue
                    else:
                        raise NotImplementedError(f"{action} for {signal} is not implemented")
                else:
                    new_context = create_signal_context(pending_sig, sigaction, process_entry.cpu_context)
                    process_entry.push_subroutine(new_context, self.process_routine(process_entry.pid))
                    process_entry.signal_received = pending_sig.value

            # check pending signals mask
            logging.info(f"scheduling proces with PID {pid}")
            self.simulator.reset_instruction_counter()
            result = next(process_entry.process_routine)
            if result:
                logging.info(f"process {pid} yielded: {result[0]} {result[1].resource}")
            else:
                logging.info(f"process {pid} yielded")
            self.scheduler.update_processes_states(process_entry, result)

        if self.initial_term_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.initial_term_settings)

    def get_pid(self):
        new_pid = max(self.process_table.keys()) + 1
        return new_pid

    def process_routine(self, pid):
        process = self.process_table[pid]
        # event loop
        while True:
            self.simulator.load_context_into_cpu(process.cpu_context)
            hardware_event = self.simulator.run()
            process.cpu_context = self.simulator.read_context_from_cpu()
            result = yield from self.react_to_event(process, hardware_event)
            self.scheduler.update_processes_states(process, result)
            logging.info(f"execution result {self.dump_result(result)}")

    def dump_result(self, result):
        if result is None:
            return "None"
        action, resource = result
        return (action, resource.resource)

    def load_process_image_from_file(self, pid, program_file: str, argv) -> ProcessImage:
        cpu_context = self.simulator.get_initial_context()
        parse_cpu_context_from_file(cpu_context, program_file, argv, [])
        process = ProcessImage(pid, cpu_context, self.process_routine(pid))
        process.command = " ".join(argv)
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
                process.signal_set.set_pending(Signal.SIGSEGV)
                raise NotImplementedError
            elif event_t == EXC_PAGE_FAULT_MISS:
                area = process.cpu_context.vm.get_area_by_va(fault_addr)
                if area is not None:
                    process.cpu_context.vm.add_page_containing_addr(fault_addr)
                elif fault_addr == SIGNAL_RETURN_ADDRESS:
                    # it means signal handler returned, restore previous context
                    # TODO: maybe we want to unset pending mask here?
                    process.pop_subroutine()
                    yield None
                else:
                    process.signal_set.set_pending(Signal.SIGSEGV)
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
    
    def __exit(self, process, status):
        assert process.zombies == []
        self.scheduler.remove_process()
        if process.pid == 1:    # I am init
            return ("unblock", Resource("child state" , process.pid))
        parent = self.process_table[process.ppid]
        parent.signal_set.set_pending(Signal.SIGCHLD)
        parent.zombies.append((process, status))
        for fd in process.fdt.keys():
            self.__unlink_fd(process, fd)
        if LOG_FD_CHANGES:
            logging.info(process.fdt)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)
        return ("unblock", Resource("child state" , process.pid))

    def exit_syscall(self, process: ProcessImage):
        # TODO: reparent zombies to init
        logging.info("       Process exited!")
        yield self.__exit(process, STATUS_EXITED)

    def get_string_from_memory(self, process: ProcessImage, string_pointer: int):
        d = ""
        virt_mem = process.cpu_context.vm
        c = virt_mem.get_byte_as_kernel(string_pointer)
        while c != 0:
            d += chr(c)
            string_pointer += 1
            c = virt_mem.get_byte_as_kernel(string_pointer)
        return d

    def __modify_sysroot_path(self, path):
        if os.path.isabs(path):
            # Substitute the prefix in the absolute path
            return Path(os.path.join(self.sysroot, os.path.relpath(path, os.path.sep)))
        else:
            candidate = (self.cwd / path).resolve()
            if self.sysroot in candidate.parents or candidate == self.sysroot:
                return self.cwd / path
            return None

    def __generate_procstat_data(self):
        proc_data = []
        zombies = []
        for process in self.scheduler.ready_queue:
            proc_data.append((process.pid, process.ppid, process.pgid, 'R', process.command))
            zombies += process.zombies
        for process, _ in self.scheduler.blocked_queue:
            proc_data.append((process.pid, process.ppid, process.pgid, 'S', process.command))
            zombies += process.zombies
        for process in self.scheduler.stopped_processes:
            proc_data.append((process.pid, process.ppid, process.pgid, 'T', process.command))
            zombies += process.zombies
        for process in zombies:
            proc_data.append((process.pid, process.ppid, process.pgid, 'Z', process.command))
        proc_data.sort(key=lambda x: x[1])
        res = ""
        for pid, ppid, pgrp, state, command in proc_data:
            res += f'0\t{pid}\t{ppid}\t{pgrp}\t0\t{state}\t{command}\n'
        return res

    def openat_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        fd = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        if fd != AT_FDCWD:
            raise NotImplementedError("Only AT_FDCWD value for file descriptor is supported")
        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        flags = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
        path = self.get_string_from_memory(process, file_name_pointer)
        path = self.__modify_sysroot_path(path)
        logging.info(f"       open file_name: {path}")
        fd = max(process.fdt.keys()) + 1
        if str(path).endswith("/dev/uart") or str(path).endswith("/dev/tty"):
            process.fdt[fd] = self.terminal
            if LOG_FD_CHANGES:
                logging.info(process.fdt)
            process.cpu_context.reg_write(REG_RET_VAL1, fd)
            process.cpu_context.reg_write(REG_RET_VAL2, 0)
        elif path == self.sysroot / "dev" / "procstat":
            data = self.__generate_procstat_data()
            ofo = VirtualFile("/dev/procstat", data)
            self.open_files_table.append(ofo)
            process.fdt[fd] = ofo
            if LOG_FD_CHANGES:
                logging.info(process.fdt)
            process.cpu_context.reg_write(REG_RET_VAL1, fd)
            process.cpu_context.reg_write(REG_RET_VAL2, 0)
            logging.info(f"{process.fdt}")
        elif os.path.exists(path):
            oflags = convert_o_flags_netbsd_to_linux(flags)
            fd = os.open(path, oflags)
            ofo = RegularFile(path, fd)
            self.open_files_table.append(ofo)
            process.fdt[fd] = ofo
            if LOG_FD_CHANGES:
                logging.info(process.fdt)
            process.cpu_context.reg_write(REG_RET_VAL1, fd)
            process.cpu_context.reg_write(REG_RET_VAL2, 0)
            logging.info(f"{process.fdt}")
        else:
            process.cpu_context.reg_write(REG_RET_VAL1, -1)
            process.cpu_context.reg_write(REG_RET_VAL2, 0)

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
        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(statbuf_ptr, stat_bytes)

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def dup2_syscall(self, process: ProcessImage):
        oldfd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        newfd = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        if newfd in process.fdt:
            process.fdt[newfd].ref_cnt -= 1
            del process.fdt[newfd]
        else:
            process.fdt[oldfd].ref_cnt += 1

        process.fdt[newfd] = process.fdt[oldfd]
        if LOG_FD_CHANGES:
            logging.info(process.fdt)
        process.cpu_context.reg_write(REG_RET_VAL1, newfd)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def dup_syscall(self, process: ProcessImage):
        oldfd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        newfd = max(process.fdt.keys()) + 1
        process.fdt[newfd] = process.fdt[oldfd]
        process.fdt[newfd].ref_cnt += 1
        if LOG_FD_CHANGES:
            logging.info(process.fdt)
        process.cpu_context.reg_write(REG_RET_VAL1, newfd)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def getcwd_syscall(self, process: ProcessImage):
        buff_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        size = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        # TODO: handle current working directory changes
        cwd = str(Path('/') / self.cwd.relative_to(self.sysroot)).encode('ascii') + b'\x00'
        if len(cwd) > size:
            raise NotImplementedError("buffer size too small!")
        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(buff_ptr, cwd)

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def sigaltstack_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def sigprocmask_syscall(self, process: ProcessImage):
        how = INT(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        set_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        oset_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        if oset_ptr != 0:
            oset = 0
            for signal in Signal:
                if process.signal_set.is_blocked(signal):
                    oset |= (1 << signal.value)
            process.cpu_context.vm.write_int(oset_ptr, oset)

        if set_ptr != 0:
            set = process.cpu_context.vm.read_int(set_ptr)
            
            if how == SIG_BLOCK:
                for signal in Signal:
                    signal_bit = 1 << signal.value
                    if set & signal_bit != 0:
                        process.signal_set.set_blocked(signal)
            elif how == SIG_UNBLOCK:
                for signal in Signal:
                    signal_bit = 1 << signal.value
                    if set & signal_bit != 0:
                        process.signal_set.unset_blocked(signal)
            elif how == SIG_SETMASK:
                for signal in Signal:
                    signal_bit = 1 << signal.value
                    if set & signal_bit != 0:
                        process.signal_set.set_blocked(signal)
                    else:
                        process.signal_set.unset_blocked(signal)
            else:
                raise NotImplementedError(f"sigprocmask: {how} - unsupported how argument")

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
        request = process.cpu_context.reg_read(REG_SYSCALL_ARG1)

        TIOCGPGRP = 0x40047477 # TODO: currenlty this always return 1
        TIOCSPGRP = 0x80047476
        TIOCGETA = 0x402c7413
        TIOCSETAW = 0x802c7415
        TIOCSETAF = 0x802c7416

        ioctl_to_termios_option = {
            TIOCSETAW: termios.TCSADRAIN,
            TIOCSETAF: termios.TCSAFLUSH,
        }

        # TODO: every other ioctl will do nothing
        if request == TIOCGPGRP:
            pgrp_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
            pgrp_bytes = self.foreground_process_group.to_bytes(4, byteorder='little')
            process.cpu_context.vm.copy_bytes_in_vm_as_kernel(pgrp_ptr, pgrp_bytes)
        elif request == TIOCSPGRP:
            pgrp_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
            pgid_bytes = process.cpu_context.vm.load_bytes_from_vm(pgrp_ptr, 4)
            pgid = int.from_bytes(pgid_bytes, 'little')
            self.foreground_process_group = pgid
        # HACK: well, currently the terminal implementation is sooo ugly,
        # please improve it in the future
        elif request == TIOCGETA:
            termios_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
            attrs_bytes = Termios.pack(self.terminal.in_canonical_mode, self.terminal.isig_flag, self.terminal.echo_flag)
            process.cpu_context.vm.copy_bytes_in_vm_as_kernel(termios_ptr, attrs_bytes)
        elif request == TIOCSETAW or request == TIOCSETAF:
            termios_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
            attrs_bytes = process.cpu_context.vm.load_bytes_from_vm(termios_ptr, Termios.SIZE)

            icanon, isig, echo = Termios.unpack(bytes(attrs_bytes))
            self.terminal.isig_flag = isig
            self.terminal.in_canonical_mode = icanon
            self.terminal.echo_flag = echo

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def getresuid_syscall(self, process: ProcessImage):
        ruid_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        euid_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        suid_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        # TODO: support more users
        root_uid = 0
        root_uid_bytes = root_uid.to_bytes(4, byteorder='little')

        if ruid_ptr != 0:
            process.cpu_context.vm.copy_bytes_in_vm_as_kernel(ruid_ptr, root_uid_bytes)
        if euid_ptr != 0:
            process.cpu_context.vm.copy_bytes_in_vm_as_kernel(euid_ptr, root_uid_bytes)
        if suid_ptr != 0:
            process.cpu_context.vm.copy_bytes_in_vm_as_kernel(suid_ptr, root_uid_bytes)

        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def getresgid_syscall(self, process: ProcessImage):
        self.getresuid_syscall(process)

    def __unlink_fd(self, process, fd):
        ofo = process.fdt[fd]
        ofo.ref_cnt -= 1
        if ofo.ref_cnt == 0 and isinstance(ofo, PipeWriteEnd):
            ofo.file_struct.write_end_closed = True

    def close_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        self.__unlink_fd(process, fd)
        del process.fdt[fd]
        if LOG_FD_CHANGES:
            logging.info(process.fdt)
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def lseek_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        offset = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        whence = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        # get the host fd
        fd = process.fdt[fd].fd

        whence_map = {
            0: os.SEEK_SET,
            1: os.SEEK_CUR,
            2: os.SEEK_END
        }

        if whence not in whence_map:
            raise NotImplementedError(f"lseek: unsupported whence - {whence}")

        res = os.lseek(fd, offset, whence_map[whence])
        process.cpu_context.reg_write(REG_RET_VAL1, res)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def getpid_syscall(self, process: ProcessImage):
        process.cpu_context.reg_write(REG_RET_VAL1, process.pid)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

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

        # supported_signals = [Signal.SIGCHLD, Signal.SIGINT, Signal.SIGQUIT]
        # if signal not in supported_signals:
        #     raise NotImplementedError(f'Unsupported syscall number: {signal}, only {supported_signals} are supported')

        data = process.cpu_context.vm.load_bytes_from_vm(new_action_pointer, Sigaction.SIZE)
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

        WNOHANG = 1
        WUNTRACED = 2

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

    def getdents_syscall(self, process: ProcessImage):
        fd = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        buff_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        nbytes = process.cpu_context.reg_read(REG_SYSCALL_ARG2)

        fd = process.fdt[fd].fd
        
        res = bytes()
        for inode, type, name in getdents_raw(fd, nbytes):
            name = bytes(name, 'utf-8') + b'\x00'
            if len(name) % 2 == 0:
                name += b'\x00'
            res += (inode & 0xffff).to_bytes(2, 'little')
            reclen = 2 + 2 + 2 + 1 + len(name)
            res += reclen.to_bytes(2, 'little')
            res += len(name).to_bytes(2, 'little')
            res += type.to_bytes(1, 'little')
            res += name

        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(buff_ptr, res)

        process.cpu_context.reg_write(REG_RET_VAL1, len(res))
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def issetugid_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 1)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def readlinkat_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL2, -1)

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

        F_DUPFD = 0
        F_SETFD = 2 # TODO: actually implement file descriptor flags
        F_GETFL = 3
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
        if LOG_FD_CHANGES:
            logging.info(process.fdt)

        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(fds_ptr, read_fd.to_bytes(4, 'little'))
        process.cpu_context.vm.copy_bytes_in_vm_as_kernel(fds_ptr + INT_SIZE, write_fd.to_bytes(4, 'little'))

    def pipe2_syscall(self, process: ProcessImage):
        # TODO: handle flags
        self.pipe_syscall(process)

    def faccessat_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def fstatat_syscall(self, process: ProcessImage):
        # TODO: add handling CWD
        fd = LONG(process.cpu_context.reg_read(REG_SYSCALL_ARG0))
        if fd != AT_FDCWD:
            raise NotImplementedError("Only AT_FDCWD value for file descriptor is supported")

        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        path = self.get_string_from_memory(process, file_name_pointer)
        path = self.__modify_sysroot_path(path)

        return_val = -1
        if path and os.path.isfile(path) or os.path.isdir(path):
            return_val = 0

            # TODO: do we really want to pass all host values?
            stat_info = os.stat(path)
            stat_bytes = Stat.pack(stat_info)
            statbuf_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
            process.cpu_context.vm.copy_bytes_in_vm(statbuf_ptr, stat_bytes)

        process.cpu_context.reg_write(REG_RET_VAL1, return_val)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def clock_gettime_syscall(self, process: ProcessImage):
        # TODO: implement it properly
        timespec_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        process.cpu_context.vm.copy_bytes_in_vm(timespec_ptr, bytes(16))
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def getppid_syscall(self, process: ProcessImage):
        process.cpu_context.reg_write(REG_RET_VAL1, process.ppid)
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

    def getpgid_syscall(self, process: ProcessImage):
        process.cpu_context.reg_write(REG_RET_VAL1, process.pgid)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def umask_syscall(self, process: ProcessImage):
        # TODO: implement it
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def chdir_syscall(self, process: ProcessImage):
        path_ptr = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        path = self.get_string_from_memory(process, path_ptr)

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
        file_name_pointer = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        argv_addr = process.cpu_context.reg_read(REG_SYSCALL_ARG1)
        envp_addr = process.cpu_context.reg_read(REG_SYSCALL_ARG2)
        argv = process.cpu_context.vm.read_string_list(argv_addr)
        env = process.cpu_context.vm.read_string_list(envp_addr)
        cpu_context = self.simulator.get_initial_context()
        path = self.__modify_sysroot_path(file_name)
        if not path:
            raise NotImplementedError(f"execve: path {path} doesn't exist")

        # the file might be binary script
        with open(path, 'rb') as f:
            first_bytes = f.read(2)
            if first_bytes == b'#!':
                interpreter_line = f.readline().decode('utf-8').strip()
                # TODO: what about other arguments?
                interpreter = interpreter_line.split()[0]
                path = self.__modify_sysroot_path(interpreter)
                # argv[0] may contain program name without a path, use filename instead
                argv = [str(path), file_name] + argv[1:]

        logging.info(f" execve file_name: {file_name}")
        # path = Path(__file__).parents[2] / "binaries" / file_name
        logging.info(f" on host it is file: {path}")
        parse_cpu_context_from_file(cpu_context, path, argv, env)
        process.cpu_context = cpu_context
        process.command = " ".join(argv)

    def setgroups_syscall(self, process: ProcessImage):
        # TODO: implement it
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def setsid_syscall(self, process: ProcessImage):
        # TODO: implement it
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def setuid_syscall(self, process: ProcessImage):
        # TODO: implement it
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def setgid_syscall(self, process: ProcessImage):
        # TODO: implement it
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

    def setitimer_syscall(self, process: ProcessImage):
        # TODO: implement it
        process.cpu_context.reg_write(REG_RET_VAL1, 0)
        process.cpu_context.reg_write(REG_RET_VAL2, 0)

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

    # TODO: should we remove syscalls below?

    def debug_print(self, process: ProcessImage):
        value = process.cpu_context.reg_read(REG_SYSCALL_ARG0)
        logging.info(f"{hex(value)}")

    def wait_syscall(self, process: ProcessImage):
        while True:
            # TODO: fix it
            if process.signal_set.is_set(Signal.SIGCHLD):
                logging.info("Received SIGCHLD when waiting!")
                process.signal_set.unset_pending(Signal.SIGCHLD)
                return
            else:
                yield ("block", Resource("child state", [child.pid for child in process.children]))


syscall_dict = {
                1: Kernel.exit_syscall,
                2:  Kernel.fork_syscall,
                3:  Kernel.read_syscall,
                4:  Kernel.write_syscall,
                5:  Kernel.openat_syscall,
                6:  Kernel.close_syscall,
                7:  Kernel.lseek_syscall,
                9:  Kernel.getpid_syscall,
                10: Kernel.kill_syscall,
                11: Kernel.fstat_syscall,
                12: Kernel.sbrk_syscall,
                13: Kernel.mmap_syscall,
                15: Kernel.getdents_syscall,
                16: Kernel.dup_syscall,
                17: Kernel.dup2_syscall,
                18: Kernel.sigaction_syscall,
                20: Kernel.wait4_syscall,
                23: Kernel.faccessat_syscall,
                24: Kernel.fstatat_syscall,
                25: Kernel.pipe2_syscall,
                26: Kernel.clock_gettime_syscall,
                28: Kernel.execve_syscall,
                29: Kernel.getppid_syscall,
                30: Kernel.setpgid_syscall,
                31: Kernel.getpgid_syscall,
                32: Kernel.umask_syscall,
                35: Kernel.chdir_syscall,
                36: Kernel.getcwd_syscall,
                37: Kernel.sigaltstack_syscall,
                38: Kernel.sigprocmask_syscall,
                39: Kernel.setcontext_syscall,
                40: Kernel.ioctl_syscall,
                41: Kernel.getresuid_syscall,
                42: Kernel.getresgid_syscall,
                45: Kernel.issetugid_syscall,
                46: Kernel.fcntl_syscall,
                49: Kernel.readlinkat_syscall,
                55: Kernel.sigsuspend_syscall,
                59: Kernel.setgroups_syscall,
                60: Kernel.setsid_syscall,
                64: Kernel.setuid_syscall,
                67: Kernel.setgid_syscall,
                81: Kernel.setitimer_syscall,
                86: Kernel.sigtimedwait_syscall,
                100: Kernel.debug_print,
                247: Kernel.wait_syscall
                }
