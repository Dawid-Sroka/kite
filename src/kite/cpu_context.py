from pyrisc.sim.components import Register, RegisterFile, Memory
from kite.consts import *

from pyrisc.sim.consts import *
from kite.consts import VPO_LENTGH, VPO_MASK

import logging
import mmap
import copy
from sortedcontainers import SortedList

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

class PageTableEntry:
    def __init__(self, vpn, prot, physical_page):
        self.vpn = vpn
        self.perms = prot
        self.physical_page = physical_page

class VMAreaStruct:
    def __init__(self, area_start, area_size, area_prot, area_flags, data):
        assert len(data) == area_size

        self.start_vpn = area_start >> VPO_LENTGH
        self.page_cnt = area_size >> VPO_LENTGH
        # dictionary of type {vpn : pte}
        self.mapped_pages = {}
        self.vm_prot = area_prot
        self.vm_flags = area_flags
        self.data = data

    def get_page(self, vpn) -> PageTableEntry:
        if vpn in self.mapped_pages.keys():
            return self.mapped_pages[vpn]
        else:
            return None


class VMAreas:
    def __init__(self):
        key_func = lambda obj: obj.start_vpn
        self.vm_areas_list = SortedList(key=key_func)

    def translate(self,vpn) -> PageTableEntry | None:
        area = self.get_area_by_vpn(vpn)
        if area is None:
            return None
        pte = area.get_page(vpn)
        return pte

    def copy_byte_in_vm(self, va, byte_to_store):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        byte_offset_in_page = (va & VPO_MASK)

        pte = self.translate(vpn)
        if pte == None:
            # there's no such page in pt
            # kernel must do something
            raise NotImplementedError
        page = pte.physical_page
        page[byte_offset_in_page] = byte_to_store

    def copy_bytes_in_vm(self, start_va, array_of_bytes):
        count = len(array_of_bytes)
        for i in range(count):
            self.copy_byte_in_vm(start_va + i, array_of_bytes[i])

    def load_byte_from_vm(self, va):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        vpo = (va & VPO_MASK)

        pte = self.translate(vpn)
        if pte == None:
            # there's no such page in pt
            # kernel must do something
            raise NotImplementedError
        page = pte.physical_page
        return page[vpo]

    def load_bytes_from_vm(self, start_va, count):
        returned_bytes = []
        for i in range(count):
            next_byte = self.load_byte_from_vm(start_va + i)
            returned_bytes.append(next_byte)
        return returned_bytes

    def copy_into_vm(self, va, data):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        vpo = (va & VPO_MASK)

        area = self.get_area_by_vpn(vpn)
        if area != None:
            if vpn not in area.mapped_pages.keys():
                area.mapped_pages[vpn] = PageTableEntry(vpn, area.vm_prot)
            area.mapped_pages[vpn].physical_page[vpo] = data
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
        vpn = addr >> VPO_LENTGH
        area = self.get_area_by_va(addr)
        if area != None:
            if vpn not in area.mapped_pages.keys():
                page_offset = (vpn - area.start_vpn) << VPO_LENTGH
                physical_page = bytearray(area.data[page_offset:page_offset + PAGE_SIZE])
                area.mapped_pages[vpn] = PageTableEntry(vpn, area.vm_prot, physical_page)
        else:
            raise NotImplementedError

    def get_byte(self, pointer: int):
        vpn = pointer >> VPO_LENTGH
        vpo = (pointer & VPO_MASK)
        pte = self.translate(vpn)
        if pte == None:
            # there's no such page in pt
            # kernel must do something
            logging.info("SIGSEGV")
            raise NotImplementedError
        if pte.perms == M_READ_ONLY or pte.perms == M_READ_WRITE:
            page = pte.physical_page
            ppo = vpo
            return page[ppo]
        else:
            logging.info("SIGSEGV")
            raise NotImplementedError

    def dump_mem_in_bytes(self, pointer, count):
        loaded_bytes = self.load_bytes_from_vm(pointer, count)
        for i in range(count):
            logging.info(f"{hex(pointer + i)} {hex(loaded_bytes[i])}")

    def dump_mem(self, pointer: int, count):

        def transparent_get_byte(pointer):
            vpn = pointer >> VPO_LENTGH
            vpo = (pointer & VPO_MASK)
            pte = self.translate(vpn)
            if pte == None:
                return 0
            if pte.perms == M_READ_ONLY or pte.perms == M_READ_WRITE:
                page = pte.physical_page
                return page[vpo]
            else:
                return 0

        for i in range(count):
            logging.info(f"{hex(pointer)} {hex(transparent_get_byte(pointer))}")
            pointer += 4
