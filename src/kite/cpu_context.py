from pyrisc.sim.components import Register, RegisterFile, Memory
from kite.consts import *

from pyrisc.sim.consts import *
from pyrisc.sim.components import TranslatesAddresses, PageTableEntry, VPO_LENTGH, VPN_MASK, VPO_MASK

#--------------------------------------------------------------------------
#   Configurations
#--------------------------------------------------------------------------

# Memory configurations
#   IMEM: 0x80000000 - 0x8000ffff (64KB)
#   DMEM: 0x80010000 - 0x8001ffff (64KB)

IMEM_START  = WORD(0x80000000)      # IMEM: 0x80000000 - 0x8000ffff (64KB)
IMEM_SIZE   = WORD(64 * 1024)
DMEM_START  = WORD(0x80010000)      # DMEM: 0x80010000 - 0x8001ffff (64KB)
DMEM_SIZE   = WORD(64 * 1024)
#--------------------------------------------------------------------------

class VMAreaStruct:
    def __init__(self, area_start, area_size, area_prot, area_flags):
        self.start_vpn = area_start >> VPO_LENTGH
        self.page_cnt = area_size >> VPO_LENTGH
        # dictionary of type {vpn : pte}
        self.cached_pages = {}
        self.vm_prot = area_prot
        self.vm_flags = area_flags

    def get_page(self, vpn) -> PageTableEntry:
        if vpn in self.cached_pages.keys():
            return self.cached_pages[vpn]
        else:
            return None


class VMAreas(TranslatesAddresses):
    def __init__(self):
        self.vm_areas_list = []

    def translate(self,vpn) -> PageTableEntry | None:
        area = self.get_area_by_vpn(vpn)
        if area is None:
            return None
        pte = area.get_page(vpn)
        return pte

    def copy_byte_in_vm(self, va, byte_to_store):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        vpo = (va & VPO_MASK)
        word_offset_in_page = vpo // WORD_SIZE
        offset_in_word = vpo % WORD_SIZE
        word_to_store = byte_to_store << (offset_in_word * 8)

        pte = self.translate(vpn)
        if pte == None:
            # there's no such page in pt
            # kernel must do something
            raise NotImplementedError
        page = pte.physical_page
        saved_word = page[word_offset_in_page]
        saved_word = saved_word & ((1 << (word_offset_in_page * 8)) - 1)
        word_to_store += saved_word
        page[word_offset_in_page] = word_to_store

    def copy_bytes_in_vm(self, start_va, array_of_bytes):
        count = len(array_of_bytes)
        for i in range(count):
            self.copy_byte_in_vm(start_va + i, array_of_bytes[i])

    def load_byte_from_vm(self, va):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        vpo = (va & VPO_MASK)
        word_offset_in_page = vpo // WORD_SIZE
        offset_in_word = vpo % WORD_SIZE

        pte = self.translate(vpn)
        if pte == None:
            # there's no such page in pt
            # kernel must do something
            raise NotImplementedError
        page = pte.physical_page
        loaded_word = page[word_offset_in_page]
        loaded_byte = (loaded_word >> (offset_in_word * 8)) & 0xFF
        return loaded_byte

    def load_bytes_from_vm(self, start_va, count):
        returned_bytes = []
        for i in range(count):
            next_byte = self.load_byte_from_vm(start_va + i)
            returned_bytes.append(next_byte)
        return returned_bytes

    def copy_into_vm(self, va, data):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        vpo = (va & VPO_MASK) // WORD_SIZE
        # pte = self.page_table.translate(vpn)

        area = self.get_area_by_vpn(vpn)
        if area != None:
            if vpn not in area.cached_pages.keys():
                area.cached_pages[vpn] = PageTableEntry(vpn, area.vm_prot)
                area.cached_pages[vpn].physical_page[vpo] = data
            else:
                area.cached_pages[vpn].physical_page[vpo] = data
        else:
            raise NotImplementedError

    def get_area_by_vpn(self, vpn) -> VMAreaStruct:
        for area in self.vm_areas_list:
            if area.start_vpn <= vpn and vpn < area.start_vpn + area.page_cnt:
                return area
        return None

    def get_area_by_va(self, va) -> VMAreaStruct:
        vpn = va >> VPO_LENTGH
        for area in self.vm_areas_list:
            if area.start_vpn <= vpn and vpn < area.start_vpn + area.page_cnt:
                return area
        return None

    def add_page_containing_addr(self, addr):
        new_page_addr = addr & VPN_MASK
        vpn = addr >> VPO_LENTGH
        area = self.get_area_by_va(addr)
        if area != None:
            if vpn not in area.cached_pages.keys():
                area.cached_pages[vpn] = PageTableEntry(vpn, area.vm_prot)
        else:
            raise NotImplementedError

    def get_byte(self, pointer: int):
        vpn = pointer >> VPO_LENTGH
        vpo = (pointer & VPO_MASK) // WORD_SIZE
        pte = self.translate(vpn)
        if pte == None:
            # there's no such page in pt
            # kernel must do something
            print("SIGSEGV")
            raise NotImplementedError
        if pte.perms == M_READ_ONLY or pte.perms == M_READ_WRITE:
            page = pte.physical_page
            ppo = vpo
            mem_word = page[ppo]
            offset = pointer % 4
            mem_byte = (mem_word >> offset * 8) & 0xFF
            return mem_byte
        else:
            print("SIGSEGV")
            raise NotImplementedError

    def dump_mem_in_bytes(self, pointer, count):
        loaded_bytes = self.load_bytes_from_vm(pointer, count)
        for i in range(count):
            print(f"{hex(pointer + i)} {hex(loaded_bytes[i])}")

    def dump_mem(self, pointer: int, count):

        def transparent_get_byte(pointer):
            vpn = pointer >> VPO_LENTGH
            vpo = (pointer & VPO_MASK) // WORD_SIZE
            pte = self.translate(vpn)
            if pte == None:
                return 0
            if pte.perms == M_READ_ONLY or pte.perms == M_READ_WRITE:
                page = pte.physical_page
                ppo = vpo
                mem_word = page[ppo]
                offset = pointer % 4
                mem_byte = (mem_word >> offset * 8) & 0xFF
                return mem_byte
            else:
                return 0

        for i in range(count):
            print(f"{hex(pointer)} {hex(transparent_get_byte(pointer))}")
            pointer += 4


class CPUContext:
    def __init__(self, pc: Register, regs: RegisterFile, vm_areas: VMAreas):
        self.pc = pc
        self.regs = regs
        self.vm = vm_areas

    @classmethod
    def create(cls):
        pc = Register()
        regs = RegisterFile()
        vm_areas = VMAreas()
        return cls(pc, regs, vm_areas)
