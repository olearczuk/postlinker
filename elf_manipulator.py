from utils import *
import shutil
from pwnlib.elf.elf import *

PAGE_SIZE = 0x1000


class ElfManipulator:

    def __init__(self, orig_name, output_name):
        shutil.copyfile(orig_name, output_name)
        self.elf = ELF(output_name)
        self.elf.stream = open(output_name, "r+b")

    def update_segments_offsets(self):
        for (i, segment) in enumerate(self.elf.segments):
            if i == 0 or i == 2:
                segment.header["p_vaddr"] -= PAGE_SIZE
                segment.header["p_paddr"] -= PAGE_SIZE
                if i == 2:
                    self.update_elf_header()
                    self.update_phdr_segment()
                    segment.header["p_filesz"] += PAGE_SIZE
                    segment.header["p_memsz"] += PAGE_SIZE
            else:
                segment.header["p_offset"] += PAGE_SIZE
            write_segment(self.elf, segment, i)

    def update_elf_header(self):
        make_gap(self.elf.stream, self.elf._segment_offset(self.elf.num_segments()), PAGE_SIZE)
        self.elf.header["e_shoff"] += PAGE_SIZE
        write_elf_header(self.elf)

    def update_phdr_segment(self):
        phdr_segment = self.elf.get_segment(0)
        phdr_segment.header["p_filesz"] += self.elf.header["e_phentsize"]
        phdr_segment.header["p_memsz"] += self.elf.header["e_phentsize"]
        write_segment(self.elf, phdr_segment, 0)

    def update_sections_offsets(self):
        for (i, section) in enumerate(self.elf.sections):
            if i == 0:
                continue
            section.header["sh_offset"] += PAGE_SIZE
            write_section(self.elf, section, i)

    def add_new_segment(self, segment):
        write_segment(self.elf, segment, self.elf.num_segments())
        self.elf.header["e_phnum"] += 1
        write_elf_header(self.elf)