from kite.cpu_context import CPUContext
from kite.process import Process, ProcessTable
from kite.scheduler import Scheduler
from kite.simulator import Simulator, Event

from kite.consts import *
from kite.loading import check_elf, parse_cpu_context_from_file

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
        print(event)
        if event == EXC_ECALL:
            self.call_syscall(process)
        elif event == EXC_CLOCK:
            # check whether time quantum elapsed
            # some action of scheduler
            pass
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


syscall_dict = {60: Kernel.exit_syscall}
