from kite.consts import *
from kite.cpu_context import VMAreaStruct, M_READ_ONLY, M_READ_WRITE
from kite.utils import round_down_to_page_size, round_up_to_page_size

from elftools.elf import elffile as elf

import logging
import mmap

def parse_cpu_context_from_file(cpu_context, program_file: str):
    logging.info(f"Loading file {program_file}")
    try:
        f = open(program_file, 'rb')
    except IOError:
        logging.info(ELF_ERR_MSG[ELF_ERR_OPEN] % program_file)
        return WORD(0)

    with f:
        ef = elf.ELFFile(f)
        efh = ef.header
        ret = check_elf(program_file, efh)
        if ret != ELF_OK:
            logging.info(ELF_ERR_MSG[ret] % program_file)
            return WORD(0)

        entry_point = WORD(efh['e_entry'])
        cpu_context.reg_write(REG_PC, entry_point)

        vm_areas_list = cpu_context.vm.vm_areas_list
        for seg in ef.iter_segments('PT_LOAD'):
            segment_offset = seg.header.p_paddr
            segment_size = max(seg.header.p_filesz, seg.header.p_memsz)

            area_offset = round_down_to_page_size(segment_offset)
            area_size = round_up_to_page_size(segment_offset + segment_size) - area_offset

            if seg.header.p_filesz != 0:
                segment_data = bytearray(area_size)
                segment_data[:segment_size] = seg.data()
                # make sure this value won't be mutable
                segment_data = bytes(segment_data)
            else:
                segment_data = bytes(area_size)

            logging.info(f"Mapping segment on <0x{area_offset:X}, 0x{area_offset + area_size:X}>")
            area = VMAreaStruct(area_offset, area_size, M_READ_ONLY, 0, segment_data)
            vm_areas_list.add(area)

    # this is stack segment, it's not defined in ELF
    # TODO: research if it's always on such offset
    # well, this depends on the system, maybe we can define something
    # that will work both for rv32 and rv64?
    stack_offset = 0x7fffff7ff000
    stack_size = 8*1024*1024 # 8MiB
    stack_pointer_initial_value = 0x7fffffffeff0
    cpu_context.reg_write(SP, stack_pointer_initial_value)
    segment_data = bytes(stack_size)
    vm_areas_list.add(VMAreaStruct(stack_offset, stack_size, M_READ_WRITE, 0, segment_data))

    cpu_context.vm.vm_areas_list = vm_areas_list
    return cpu_context

def check_elf(filename, header):
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
