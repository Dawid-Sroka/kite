from pyrisc.sim.components import Register, RegisterFile, Memory
from kite.consts import *

from pyrisc.sim.components import TranslatesAddresses, PageTableEntry, VPO_LENTGH, VPN_MASK

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

    def copy_into_vm(self, va, data):
        vpn = va >> VPO_LENTGH
        VPO_MASK = 2**VPO_LENTGH - 1
        vpo = (va & VPO_MASK) // WORD_SIZE
        # pte = self.page_table.translate(vpn)

        area = self.get_area_by_vpn(vpn)
        if area != None:
            if vpn not in area.cached_pages.keys():
                area.cached_pages[vpn] = PageTableEntry(vpn)
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
                area.cached_pages[vpn] = PageTableEntry(vpn)
        else:
            raise NotImplementedError

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
