from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from utils import *
import shutil
from pwnlib.elf.elf import *

PAGE_SIZE = 0x1000

SHF_ALLOC = 0x2
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4

PF_EXECUTE = 0x1
PF_WRITE = 0x2
PF_READ = 0x4


class ElfManipulator:

    def __init__(self, orig_name, rel_name, output_name):
        shutil.copyfile(orig_name, output_name)
        self.exec_elf = ELF(output_name)
        self.exec_elf.stream = open(output_name, "r+b")
        self.rel_elf = ELFFile(open(rel_name, "rb"))
        self.exec_sections = []
        self.write_sections = []
        self.exec_write_sections = []
        self.other_sections = []
        self.text_section = None
        self.entry_symbol_offset = 0

    def update_segments_offsets(self):
        for (i, segment) in enumerate(self.exec_elf.segments):
            if i == 0 or i == 2:
                segment.header["p_vaddr"] -= PAGE_SIZE
                segment.header["p_paddr"] -= PAGE_SIZE
                if i == 2:
                    make_gap(self.exec_elf.stream, self.exec_elf._segment_offset(self.exec_elf.num_segments()), PAGE_SIZE)
                    self.exec_elf.header["e_shoff"] += PAGE_SIZE
                    write_elf_header(self.exec_elf)
                    segment.header["p_filesz"] += PAGE_SIZE
                    segment.header["p_memsz"] += PAGE_SIZE
            else:
                segment.header["p_offset"] += PAGE_SIZE
            write_segment(self.exec_elf, segment, i)

    def update_sections_offsets(self):
        for (i, section) in enumerate(self.exec_elf.sections):
            if i == 0:
                continue
            section.header["sh_offset"] += PAGE_SIZE
            write_section(self.exec_elf, section, i)

    def get_base_address(self):
        first_segment = self.exec_elf.get_segment(0)
        return first_segment.header["p_vaddr"] - first_segment.header["p_offset"]

    def combine_sections(self, sections, segment_flags):
        if len(sections) == 0:
            return
        # padding stream to PAGE_SIZE
        alignment = (self.get_base_address() + get_stream_size(self.exec_elf.stream)) % PAGE_SIZE
        if alignment != 0:
            expand_stream(self.exec_elf.stream, PAGE_SIZE - alignment)
        segment_offset = get_stream_size(self.exec_elf.stream)
        entry_symbol_offset = 0
        # adding sections
        for section in sections:
            section_offset = section.header["sh_offset"]
            section_size = section.header["sh_size"]
            # aligning section address
            alignment = (self.get_base_address() + get_stream_size(self.exec_elf.stream)) % section.header["sh_addralign"]
            if alignment != 0:
                expand_stream(self.exec_elf.stream, section.header["sh_addralign"] - alignment)

            # optionally updating ELF header entry
            if self.text_section["sh_name"] == section["sh_name"]:
                entry_symbol_offset = get_stream_size(self.exec_elf.stream) + self.entry_symbol_offset

            expand_stream(self.exec_elf.stream, section_size)
            # reading section content
            self.rel_elf.stream.seek(section_offset)
            section_content = self.rel_elf.stream.read(section_size)
            # writing section content
            self.exec_elf.stream.seek(get_stream_size(self.exec_elf.stream) - section_size)
            self.exec_elf.stream.write(section_content)

        segment_headers = dict({
            "p_type": "PT_LOAD",
            "p_flags": segment_flags,
            "p_offset": segment_offset,
            "p_vaddr": self.get_base_address() + segment_offset,
            "p_paddr": self.get_base_address() + segment_offset ,
            "p_filesz": get_stream_size(self.exec_elf.stream) - segment_offset,
            "p_memsz": get_stream_size(self.exec_elf.stream) - segment_offset,
            "p_align": PAGE_SIZE,
        })
        segment = Segment(segment_headers, self.exec_elf.stream)
        write_segment(self.exec_elf, segment, self.exec_elf.num_segments())

        # updating phdr_segment
        phdr_segment = self.exec_elf.get_segment(0)
        phdr_segment.header["p_filesz"] += self.exec_elf.header["e_phentsize"]
        phdr_segment.header["p_memsz"] += self.exec_elf.header["e_phentsize"]
        write_segment(self.exec_elf, phdr_segment, 0)
        # updating ELF header
        if entry_symbol_offset > 0:
            self.exec_elf.header["e_entry"] = segment.header["p_vaddr"] + entry_symbol_offset - segment.header["p_offset"]
        self.exec_elf.header["e_phnum"] += 1
        write_elf_header(self.exec_elf)

    def fetch_rel_sections(self):
        self.entry_symbol_offset, text_section_index = self.get_entry_symbol_info()
        self.exec_sections = []
        self.write_sections = []
        self.exec_write_sections = []
        self.other_sections = []
        section_index = 0
        for section in self.rel_elf.iter_sections():
            if section_index == text_section_index:
                self.text_section = section
            flags = section.header["sh_flags"]
            section_size = section.header["sh_size"]
            if flags & SHF_ALLOC and section_size > 0:
                cur_flags = flags & (SHF_WRITE + SHF_EXECINSTR)
                if cur_flags == SHF_EXECINSTR:
                    self.exec_sections.append(section)
                elif cur_flags == SHF_WRITE:
                    self.write_sections.append(section)
                elif cur_flags == SHF_WRITE + SHF_EXECINSTR:
                    self.exec_write_sections.append(section)
                else:
                    self.other_sections.append(section)
            section_index += 1

    def get_entry_symbol_info(self):
        symbol_table = self.rel_elf.get_section_by_name(".symtab")
        if symbol_table is None:
            return 0, -1
        entry_symbols = symbol_table.get_symbol_by_name("_start")
        if entry_symbols is None:
            return 0, -1
        return entry_symbols[0].entry["st_value"], entry_symbols[0].entry["st_shndx"]