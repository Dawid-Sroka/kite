from kite.cpu_context import CPUContext, VMAreaStruct
from kite.process import Process, ProcessTable
from kite.scheduler import Scheduler
from kite.simulator import Simulator

from kite.consts import *
from kite.loading import check_elf, parse_cpu_context_from_file

from pathlib import Path

from pyrisc.sim.sim import Event, MemEvent

class Kernel:

    def __init__(self, simulator: Simulator, scheduler: Scheduler):
        self.simulator = simulator
        self.process_table = ProcessTable()
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
        self.scheduler.enqueue_process(init)

        # może samą pętlę wydzielić do funkcji main_loop. Tak jest w kernelu
        while True:
            # Może jednak chcę tutaj używać PID
            process = self.scheduler.get_process()
            if process is None:
                print("No more processes!")
                break
            self.simulator.load_context_into_cpu(process.cpu_context)
            cpu_event = self.simulator.run()
            process.cpu_context = self.simulator.read_context_from_cpu()
            # procedura react zakłada, że dostaje running proces i możę zmienić jego stan
            self.react_to_event(process, cpu_event)

    def load_process_from_file(self, program_file: str) -> Process:
        cpu_context = parse_cpu_context_from_file(program_file)
        process = Process(cpu_context)
        self.process_table.add(process) # nadać pid
        return process

    def react_to_event(self, process: Process, event: Event) -> None:
        # event, addr = cpu_event
        event_t = event.type
        print("event: " + EXC_MSG[event_t])
        # Add Interrupt Descriptor Table??
        if event_t == EXC_ECALL:
            self.call_syscall(process)
        elif event_t == EXC_CLOCK:
            # check whether time quantum elapsed
            # some action of scheduler
            pass
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

# --------------------------------------------------------------------------
#   syscall implementations
# --------------------------------------------------------------------------

    def call_syscall(self, process: Process):
        syscall_no = process.cpu_context.regs.read(REG_SYSCALL_NUMBER)
        print("syscall number = " + str(syscall_no))
        return syscall_dict[syscall_no](self, process)

    def exit_syscall(self, process: Process):
        print("Process exited!")
        self.scheduler.remove_process()


    def get_string_from_memory(self, process: Process, string_pointer: int):
        d = ""
        virt_mem = process.cpu_context.vm
        c = virt_mem.get_byte(string_pointer)
        while c != 0:
            d += chr(c)
            string_pointer += 1
            c = virt_mem.get_byte(string_pointer)
        return d

    def write_syscall(self, process: Process):
        print("I write!")

    def execve_syscall(self, process: Process):
        print("execve invoked!")
        file_name_pointer = process.cpu_context.regs.read(REG_SYSCALL_ARG0)
        file_name = self.get_string_from_memory(process, file_name_pointer)
        print("execve file_name:", file_name)
        path = Path(__file__).parents[2] / "binaries" / file_name
        new_context = parse_cpu_context_from_file(path)
        process.cpu_context = new_context

syscall_dict = {
                1:  Kernel.write_syscall,
                59: Kernel.execve_syscall,
                60: Kernel.exit_syscall
                }
