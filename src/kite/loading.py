from kite.consts import *
from kite.cpu_context import VMAreaStruct, M_READ_ONLY, M_READ_WRITE
from kite.utils import round_down_to_page_size, round_up_to_page_size

from elftools.elf import elffile as elf

import logging

def parse_cpu_context_from_file(cpu_context, program_file: str, argv, env):
    logging.info(f"Loading file {program_file}")
    try:
        f = open(program_file, 'rb')
    except IOError:
        logging.info(ELF_ERR_MSG[ELF_ERR_OPEN] % program_file)

    with f:
        ef = elf.ELFFile(f)
        efh = ef.header
        ret = check_elf(efh)
        if ret != ELF_OK:
            logging.info(ELF_ERR_MSG[ret] % program_file)

        entry_point = np.uint64(efh['e_entry'])
        cpu_context.reg_write(REG_PC, entry_point)

        initial_brk = 0x0
        vm_areas_list = cpu_context.vm.vm_areas_list
        for seg in ef.iter_segments('PT_LOAD'):
            segment_offset = seg.header.p_paddr
            segment_size = max(seg.header.p_filesz, seg.header.p_memsz)

            area_offset = round_down_to_page_size(segment_offset)
            area_size = round_up_to_page_size(segment_offset + segment_size) - area_offset

            if seg.header.p_filesz != 0:
                segment_data = bytearray(area_size)
                segment_data[:len(seg.data())] = seg.data()
            else:
                segment_data = bytearray(area_size)

            logging.info(f"Mapping segment on <0x{area_offset:X}, 0x{area_offset + area_size:X}>")
            area = VMAreaStruct(area_offset, area_size, M_READ_ONLY, 0, segment_data)
            initial_brk = max(initial_brk, area_offset + area_size)
            vm_areas_list.add(area)

    # Adjust stack size based on bitness
    if ef.elfclass == 32:
        stack_offset = STACK_32_BIT_TOP
        stack_size = STACK_32_BIT_SIZE
    else:
        stack_offset = STACK_64_BIT_TOP
        stack_size = STACK_64_BIT_SIZE
    stack_pointer_initial_value = stack_offset + stack_size - 0x1000
    cpu_context.reg_write(REG_SP, stack_pointer_initial_value)
    segment_data = bytearray(stack_size)
    vm_areas_list.add(VMAreaStruct(stack_offset, stack_size, M_READ_WRITE, 0, segment_data))

    cpu_context.vm.vm_areas_list = vm_areas_list
    cpu_context.vm.initial_brk = initial_brk
    cpu_context.vm.brk = initial_brk


def check_elf(header):
        e_ident = header['e_ident']

        # This is already checked during ELFFile()
        '''
        if bytes(e_ident['EI_MAG']) != b'\x7fELF':
            logging.info("File %s is not an ELF file" % filename)
            return False
        '''

        if e_ident['EI_DATA'] != 'ELFDATA2LSB':
            return ELF_ERR_DATA
        if header['e_type'] != 'ET_EXEC':
            return ELF_ERR_TYPE
        # Old elftools do not recognize EM_RISCV
        if header['e_machine'] != 'EM_RISCV' and header['e_machine'] != 243:
            return ELF_ERR_MACH
        return ELF_OK
