from kite.consts import *

def check_elf(filename, header):
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
