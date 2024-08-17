from kite.consts import *
from kite.cpu_context import CPUContext, VMAreas, VMAreaStruct, M_READ_ONLY, M_READ_WRITE

from elftools.elf import elffile as elf

def parse_cpu_context_from_file(program_file: str) -> CPUContext | WORD:
    cpu_context = CPUContext.create()
    vm_areas_list = [VMAreaStruct(0x80000000, 0x00010000, M_READ_ONLY, 0),
                     VMAreaStruct(0x80010000, 0x00010000, M_READ_WRITE, 0)]
    cpu_context.vm.vm_areas_list = vm_areas_list
    print("# " + "Loading file %s" % program_file)
    try:
        f = open(program_file, 'rb')
    except IOError:
        print("# " + ELF_ERR_MSG[ELF_ERR_OPEN] % program_file)
        return WORD(0)

    with f:
        ef = elf.ELFFile(f)
        efh = ef.header
        ret = check_elf(program_file, efh)
        if ret != ELF_OK:
            print("# " + ELF_ERR_MSG[ret] % program_file)
            return WORD(0)

        entry_point = WORD(efh['e_entry'])
        cpu_context.pc.write(entry_point)

        for seg in ef.iter_segments():
            addr = seg.header['p_vaddr']
            memsz = seg.header['p_memsz']
            if seg.header['p_type'] != 'PT_LOAD':
                continue
            # if addr >= cpu_context.imem.mem_start and addr + memsz < cpu_context.imem.mem_end:
            #     mem = cpu_context.imem
            # elif addr >= cpu_context.dmem.mem_start and addr + memsz < cpu_context.dmem.mem_end:
            #     mem = cpu_context.dmem
            # else:
            #     print("# " + "Invalid address range: 0x%08x - 0x%08x" \
            #         % (addr, addr + memsz - 1))
            #     continue
            image = seg.data()
            for i in range(0, len(image), WORD_SIZE):
                c = int.from_bytes(image[i:i+WORD_SIZE], byteorder='little')
                cpu_context.vm.copy_into_vm(addr, c)
                addr += WORD_SIZE
    return cpu_context

def check_elf(filename, header):
        e_ident = header['e_ident']

        # This is already checked during ELFFile()
        '''
        if bytes(e_ident['EI_MAG']) != b'\x7fELF':
            print("# " + "File %s is not an ELF file" % filename)
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
