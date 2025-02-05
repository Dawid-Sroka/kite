from kite.consts import *
from kite.cpu_context import VMAreaStruct, M_READ_ONLY, M_READ_WRITE
from kite.utils import round_up_to_page_size

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

        vm_areas_list = []
        for seg in ef.iter_segments('PT_LOAD'):
            file_size = seg.header.p_filesz
            area_size = round_up_to_page_size(file_size)
            segment_data = bytearray(area_size)
            segment_data[:file_size] = seg.data()
            # make sure this value won't be mutable
            segment_data = bytes(segment_data)
            area = VMAreaStruct(seg.header.p_paddr, area_size, M_READ_ONLY, 0, segment_data)
            vm_areas_list.append(area)

    # this is stack segment, it's not defined in ELF
    # TODO: research if it's always on such offset
    segment_data = bytes(0x10000)
    vm_areas_list.append(VMAreaStruct(0x80010000, 0x00010000, M_READ_WRITE, 0, segment_data))

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
