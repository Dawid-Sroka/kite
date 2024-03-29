from kite.cpu_context import CPUContext
from kite.process import Process, ProcessTable
from kite.scheduler import Scheduler
from kite.simulator import Simulator, Event

from elftools.elf import elffile as elf
from kite.consts import *

# --------------------------------------------------------------------------
#   Program: loads an ELF file into memory and supports disassembling
# --------------------------------------------------------------------------

ELF_OK              = 0
ELF_ERR_OPEN        = 1
ELF_ERR_CLASS       = 2
ELF_ERR_DATA        = 3
ELF_ERR_TYPE        = 4
ELF_ERR_MACH        = 5

ELF_ERR_MSG = {
    ELF_ERR_OPEN    : 'File %s not found',
    ELF_ERR_CLASS   : 'File %s is not a 32-bit ELF file',
    ELF_ERR_DATA    : 'File %s is not a little-endian ELF file',
    ELF_ERR_TYPE    : 'File %s is not an executable file',
    ELF_ERR_MACH    : 'File %s is not an RISC-V executable file',
}

# Register aliases:

RA                      = 1
SP                      = 2


REG_SYSCALL_ARG0        = 10
REG_SYSCALL_ARG1        = 11
REG_SYSCALL_ARG2        = 12
REG_SYSCALL_ARG3        = 13
REG_SYSCALL_ARG4        = 14
REG_SYSCALL_ARG5        = 15

REG_SYSCALL_NUMBER      = 17

REG_RET_VAL1            = 10
REG_RET_VAL2            = 11


class Kernel:

    def exit_syscall(self, process: Process):
        print("Process exited!")
        self.scheduler.remove_process()

    def __init__(self, simulator: Simulator, scheduler: Scheduler):
        self.simulator = simulator
        self.process_table = ProcessTable()
        self.scheduler = scheduler
        #self.vfs

    def call_syscall(self, process: Process):
        syscall_no = process.cpu_context.regs.read(REG_SYSCALL_NUMBER)
        print("syscall number = " + str(syscall_no))
        return syscall_dict[syscall_no](self, process)

    def react_to_event(self, process: Process, event: Event) -> None:
        print(event)
        if (event == EXC_ECALL):
            self.call_syscall(process)
        elif (event == EXC_CLOCK):
            # check whether time quantum elapsed
            # some action of scheduler
            pass
        else:
            raise NotImplementedError
            # break

    def check_elf(self, filename, header):
        e_ident = header['e_ident']

        # This is already checked during ELFFile()
        '''
        if bytes(e_ident['EI_MAG']) != b'\x7fELF':
            print("File %s is not an ELF file" % filename)
            return False
        '''

        if e_ident['EI_CLASS'] != 'ELFCLASS32':
            return ELF_ERR_CLASS
        if e_ident['EI_DATA'] != 'ELFDATA2LSB':
            return ELF_ERR_DATA
        if header['e_type'] != 'ET_EXEC':
            return ELF_ERR_TYPE
        # Old elftools do not recognize EM_RISCV
        if header['e_machine'] != 'EM_RISCV' and header['e_machine'] != 243:
            return ELF_ERR_MACH
        return ELF_OK

    def load_process_from_file(self, program_file: str) -> Process:

        cpu_context = CPUContext.create()
        print("Loading file %s" % program_file)
        try:
            f = open(program_file, 'rb')
        except IOError:
            print(ELF_ERR_MSG[ELF_ERR_OPEN] % program_file)
            return WORD(0)

        with f:
            ef = elf.ELFFile(f)
            efh = ef.header
            ret = self.check_elf(program_file, efh)
            if ret != ELF_OK:
                print(ELF_ERR_MSG[ret] % program_file)
                return WORD(0)

            entry_point = WORD(efh['e_entry'])
            cpu_context.pc.write(entry_point)

            for seg in ef.iter_segments():
                addr = seg.header['p_vaddr']
                memsz = seg.header['p_memsz']
                if seg.header['p_type'] != 'PT_LOAD':
                    continue
                if addr >= cpu_context.imem.mem_start and addr + memsz < cpu_context.imem.mem_end:
                    mem = cpu_context.imem
                elif addr >= cpu_context.dmem.mem_start and addr + memsz < cpu_context.dmem.mem_end:
                    mem = cpu_context.dmem
                else:
                    print("Invalid address range: 0x%08x - 0x%08x" \
                        % (addr, addr + memsz - 1))
                    continue
                image = seg.data()
                for i in range(0, len(image), WORD_SIZE):
                    c = int.from_bytes(image[i:i+WORD_SIZE], byteorder='little')
                    mem.access(True, addr, c, M_XWR)
                    addr += WORD_SIZE
        process = Process(cpu_context)
        self.process_table.add(process) # nadać pid
        return process

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

    @classmethod
    def create(cls):
        simulator = Simulator.create()
        scheduler = Scheduler()
        kernel = cls(simulator, scheduler)
        return kernel


syscall_dict = {60: Kernel.exit_syscall}
