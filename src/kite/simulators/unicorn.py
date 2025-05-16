from kite.cpu_context import VMAreas
from kite.simulators.simulator import CPUContext

from kite.consts import Event, MemEvent

from kite.consts import *

from unicorn import *
from unicorn.riscv_const import *

import ctypes
import logging

reg_to_unicorn_reg = {
    REG_PC: UC_RISCV_REG_PC,
    RA: UC_RISCV_REG_RA,
    SP: UC_RISCV_REG_SP,
    REG_SYSCALL_ARG0: UC_RISCV_REG_A0,
    REG_SYSCALL_ARG1: UC_RISCV_REG_A1,
    REG_SYSCALL_ARG2: UC_RISCV_REG_A2,
    REG_SYSCALL_ARG3: UC_RISCV_REG_A3,
    REG_SYSCALL_ARG4: UC_RISCV_REG_A4,
    REG_SYSCALL_ARG5: UC_RISCV_REG_A5,
    REG_SYSCALL_NUMBER: UC_RISCV_REG_A7,
    REG_RET_VAL1: UC_RISCV_REG_A0,
    REG_RET_VAL2: UC_RISCV_REG_A1,
}

def reg_read(obj, reg):
    if reg not in reg_to_unicorn_reg:
        raise NotImplemented
    unicorn_reg = reg_to_unicorn_reg[reg]
    return obj.reg_read(unicorn_reg)

def reg_write(obj, reg, value):
    if reg not in reg_to_unicorn_reg:
        raise NotImplemented
    unicorn_reg = reg_to_unicorn_reg[reg]
    obj.reg_write(unicorn_reg, value)

class UnicornContext:
    def __init__(self, unicorn_context, vm_areas: VMAreas):
        self.uc_context = unicorn_context
        self.vm = vm_areas

    def reg_read(self, reg):
        return reg_read(self.uc_context, reg)

    def reg_write(self, reg, value):
        reg_write(self.uc_context, reg, value)

class UnicornSimulator:
    def __init__(self):
        def hook_intr(cpu, intno, _):
            if intno == EXC_EBREAK:
                cpu.emu_stop()
                self.event = Event(EXC_ECALL)
            else:
                raise NotImplemented
        def hook_protected_mem(cpu, _type, address, _size, _value, _user_data):
            pc = self.reg_read(REG_PC)
            self.event = MemEvent(EXC_PAGE_FAULT_PERMS, address, pc)
            return False
        def hook_unmapped_mem(cpu, _type, address, _size, _value, _user_data):
            pc = self.reg_read(REG_PC)
            self.event = MemEvent(EXC_PAGE_FAULT_MISS, address, pc)
            return False

        def count_instructions(_uc, addr, _size, _user_data):
            self.instructions_left -= 1

        cpu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)

        # Enable FPU

        current_mstatus = cpu.reg_read(UC_RISCV_REG_MSTATUS)
        # Set the FS (Floating-Point Status) field to 0b11 (active state)
        MSTATUS_FS = (3 << 13)
        cpu.reg_write(UC_RISCV_REG_MSTATUS, current_mstatus | MSTATUS_FS)

        cpu.hook_add(UC_HOOK_CODE, count_instructions)
        cpu.hook_add(UC_HOOK_INTR, hook_intr)
        cpu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped_mem)
        cpu.hook_add(UC_HOOK_MEM_PROT, hook_protected_mem)

        self.cpu = cpu
        self.event = None
        self.CLOCK_CYCLES = 100000
        self.bitness = 64
        self.vm = VMAreas(self.bitness)
        self.instructions_left = self.CLOCK_CYCLES

    def get_initial_context(self) -> CPUContext:
        # TODO: clear the context
        return UnicornContext(self.cpu.context_save(), VMAreas(self.bitness))

    def load_context_into_cpu(self, cpu_context: CPUContext) -> None:
        self.cpu.context_restore(cpu_context.uc_context)
        self.vm = cpu_context.vm
        for area in self.vm.vm_areas_list:
            for page in area.mapped_pages.values():
                page_ptr = ctypes.cast(ctypes.pointer(ctypes.c_ubyte.from_buffer(page.physical_page)), ctypes.c_void_p)
                self.cpu.mem_map_ptr(page.vpn << VPO_LENTGH, PAGE_SIZE, UC_PROT_ALL, page_ptr)

    def read_context_from_cpu(self) -> CPUContext:
        uc_context = self.cpu.context_save()
        for area in self.vm.vm_areas_list:
            for page in area.mapped_pages.values():
                self.cpu.mem_unmap(page.vpn << VPO_LENTGH, PAGE_SIZE)
        return UnicornContext(uc_context, self.vm)

    def reg_read(self, reg):
        return reg_read(self.cpu, reg)

    def reg_write(self, reg, value):
        reg_write(self.cpu, reg, value)

    __allowed_errors = [
        UC_ERR_READ_UNMAPPED,
        UC_ERR_READ_PROT,
        UC_ERR_WRITE_UNMAPPED,
        UC_ERR_WRITE_PROT,
        UC_ERR_FETCH_UNMAPPED,
        UC_ERR_FETCH_PROT
    ]

    def reset_instruction_counter(self):
        self.instructions_left = self.CLOCK_CYCLES

    def run(self):
        self.event = Event(EXC_CLOCK)
        try:
            self.cpu.emu_start(self.cpu.reg_read(UC_RISCV_REG_PC), -1, 0, self.instructions_left)
        except UcError as e:
            if e.errno in UnicornSimulator.__allowed_errors:
                return self.event
            raise NotImplemented
        return self.event
