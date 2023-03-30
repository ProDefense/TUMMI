import os
import sys

import yara

class DefaultUnpacker(object):
    def init(self, sample):
        self.name = "unknown"
        self.sample = sample

        self.secs = sample.sections
        self.BASE_ADDR = sample.opt_header.ImageBase
        self.ep = sample.opt_header.AddressOfEntryPoint + self.BASE_ADDR
        self.allowed_sections = [s.Name for s in self.secs if
                                 s.VirtualAddress + self.BASE_ADDR <= self.ep < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR]

        self.section_hopping_control = len(self.allowed_sections) > 0
        self.write_execute_control = False
        self.allowed_addr_ranges = []
        self.virtualmemorysize = None

        self.startaddr = self.get_entrypoint()
        self.endaddr = self.get_tail_jump()

    def get_tail_jump(self):
        while True:
            try:
                endaddr = input("Define manual end address for emulation (leave empty for max value): ")
                if endaddr == "":
                    return sys.maxsize
                endaddr = int(endaddr, 0)
                break
            except ValueError:
                print("Incorrect end address!")
        return endaddr

    def get_entrypoint(self):
        while True:
            try:
                startaddr = input(
                    "Define manual start address for emulation or enter ep to use the entry point of the binary: ")
                if startaddr == 'ep' or startaddr == "":
                    return
                else:
                    startaddr = int(startaddr, 0)
                break
            except ValueError:
                print("Incorrect start address!")
        return startaddr

    def dump(self, uc, apicall_handler, sample, path="unpacked.exe"):
        self.dumper.dump_image(uc, self.BASE_ADDR, self.virtualmemorysize, apicall_handler, sample, path)

    def is_allowed(self, address):
        for start, end in self.allowed_addr_ranges:
            if start <= address <= end:
                return True
        return False

    def allow(self, address):
        sec_name = self.get_section(address)
        curr_section_range = self.get_section_range(sec_name)
        if curr_section_range:
            self.allowed_sections += [sec_name]
            self.allowed_addr_ranges = self.get_allowed_addr_ranges()

    def get_allowed_addr_ranges(self):
        allowed_ranges = []
        for s in self.secs:
            if s.Name in self.allowed_sections:
                start_addr = s.VirtualAddress + self.BASE_ADDR
                end_addr = s.VirtualSize + start_addr + self.BASE_ADDR
                allowed_ranges += [(start_addr, end_addr)]
        return allowed_ranges

    def get_section(self, address):
        for s in self.secs:
            if s.VirtualAddress + self.BASE_ADDR <= address < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR:
                return s.Name
        return "external"

    def get_section_from_addr(self, address):
        for s in self.secs:
            if s.VirtualAddress + self.BASE_ADDR <= address < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR:
                return s.VirtualAddress + self.BASE_ADDR, s.VirtualAddress + s.VirtualSize + self.BASE_ADDR
        return None, None

    def get_section_range(self, section):
        for s in self.secs:
            if s.Name == section:
                return s.VirtualAddress + self.BASE_ADDR, s.VirtualAddress + s.VirtualSize + self.BASE_ADDR
        return None

class AutomaticDefaultUnpacker(DefaultUnpacker):

    def get_entrypoint(self):
        return None  # default binary ep

    def get_tail_jump(self):
        return sys.maxsize

class MEWUnpacker(AutomaticDefaultUnpacker):
    def init(self, sample):
        super().init(sample)
        self.name = "MEW"
        self.allowed_sections = []
        self.section_hopping_control = True

    def is_allowed(self, address):
        return "MEW" not in self.get_section(address)