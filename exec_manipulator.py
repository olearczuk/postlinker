from elftools.construct import *
from elftools.elf.segments import Segment
from utils import *
import shutil
from pwnlib.elf.elf import *
from rel_reader import *

PAGE_SIZE = 0x1000

PF_EXECUTE = 0x1
PF_WRITE = 0x2
PF_READ = 0x4


class ExecManipulator:

    def __init__(self, orig_name, rel_name, output_name):
        shutil.copyfile(orig_name, output_name)
        self.exec_elf = ELF(output_name)
        self.exec_elf.stream = open(output_name, "r+b")
        self.rel_reader = RelReader(rel_name)
        self.rel_sections_offsets_dict = dict()

    def update_segments_offsets(self):
        first_segment = self.exec_elf.get_segment(0)
        if first_segment.header["p_type"] == "PT_PHDR":
            segment_table_size = first_segment["p_filesz"]
        else:
            segment_table_size = self.exec_elf._segment_offset(self.exec_elf.num_segments())
        for (i, segment) in enumerate(self.exec_elf.segments):
            if segment["p_offset"] < segment_table_size:
                segment.header["p_vaddr"] = max(segment.header["p_vaddr"] - PAGE_SIZE, 0)
                segment.header["p_paddr"] = max(segment.header["p_paddr"] - PAGE_SIZE, 0)
                if segment["p_type"] == "PT_LOAD":
                    segment.header["p_filesz"] += PAGE_SIZE
                    segment.header["p_memsz"] += PAGE_SIZE
            else:
                segment.header["p_offset"] += PAGE_SIZE

            print(segment.header)
            write_segment(self.exec_elf, segment, i)
        make_gap(self.exec_elf.stream, self.exec_elf._segment_offset(self.exec_elf.num_segments()), PAGE_SIZE)
        self.exec_elf.header["e_shoff"] += PAGE_SIZE
        write_elf_header(self.exec_elf)

    def update_sections_offsets(self):
        for (i, section) in enumerate(self.exec_elf.sections):
            if i == 0:
                continue
            section.header["sh_offset"] += PAGE_SIZE
            write_section(self.exec_elf, section, i)

    def generate_new_segments(self):
        fetch_rel_sections = self.rel_reader.fetch_rel_sections
        self._combine_sections(fetch_rel_sections(SHF_WRITE), PF_WRITE + PF_READ)
        self._combine_sections(fetch_rel_sections(SHF_EXECINSTR + SHF_WRITE), PF_EXECUTE + PF_WRITE + PF_READ)
        self._combine_sections(fetch_rel_sections(0), PF_READ)
        self._combine_sections(fetch_rel_sections(SHF_EXECINSTR), PF_EXECUTE + PF_READ)

    def _get_base_address(self):
        first_segment = self.exec_elf.get_segment(0)
        return first_segment.header["p_vaddr"] - first_segment.header["p_offset"]

    def _combine_sections(self, sections, segment_flags):
        if len(sections) == 0:
            return
        # padding stream to PAGE_SIZE
        alignment = (self._get_base_address() + get_stream_size(self.exec_elf.stream)) % PAGE_SIZE
        if alignment != 0:
            expand_stream(self.exec_elf.stream, PAGE_SIZE - alignment)
        segment_offset = get_stream_size(self.exec_elf.stream)
        # adding sections
        for section in sections:
            rel_section_offset = section.header["sh_offset"]
            section_size = section.header["sh_size"]
            # aligning section address
            alignment = (self._get_base_address() + get_stream_size(self.exec_elf.stream)) % section.header["sh_addralign"]
            if alignment != 0:
                expand_stream(self.exec_elf.stream, section.header["sh_addralign"] - alignment)

            # optionally updating ELF header entry
            exec_section_offset = get_stream_size(self.exec_elf.stream)
            self.rel_sections_offsets_dict[section.name] = exec_section_offset

            section_content = self.rel_reader.get_stream_content(rel_section_offset, section_size)
            expand_stream(self.exec_elf.stream, section_size)
            # writing section content
            self.exec_elf.stream.seek(get_stream_size(self.exec_elf.stream) - section_size)
            self.exec_elf.stream.write(section_content)

        segment_headers = dict({
            "p_type": "PT_LOAD",
            "p_flags": segment_flags,
            "p_offset": segment_offset,
            "p_vaddr": self._get_base_address() + segment_offset,
            "p_paddr": self._get_base_address() + segment_offset,
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
        # updating data related to .text section in REL file
        rel_text_section_offset = self.rel_sections_offsets_dict.get(".text", -1)
        rel_entry_symbol_offset = self.rel_reader.get_symbol_offset("_start")
        if rel_text_section_offset != -1 and rel_entry_symbol_offset != -1:
            entry_symbol_offset = rel_text_section_offset + self.rel_reader.get_symbol_offset("_start")
            self._set_relocations()
            self.exec_elf.header["e_entry"] = segment.header["p_vaddr"] + entry_symbol_offset - segment.header["p_offset"]
        self.exec_elf.header["e_phnum"] += 1
        write_elf_header(self.exec_elf)

    def _set_relocations(self):
        rel_text_section_offset = self.rel_sections_offsets_dict[".text"]
        formatter32 = SLInt32("")
        formatter64 = ULInt64("")
        exec_symbol_table = self.exec_elf.get_section_by_name(".symtab")

        for reloc in self.rel_reader.get_relocations():
            symbol = self.rel_reader.get_symbol(reloc["r_info_sym"])
            if is_symbol_extern(symbol):
                if symbol.name == "orig_start":
                    symbol_address = self.exec_elf.header["e_entry"]
                else:
                    symbols = exec_symbol_table.get_symbol_by_name(symbol.name)
                    symbol_address = symbols[0]["st_value"]
            else:
                symbol_type = symbol["st_info"]["type"]
                if symbol_type == "STT_SECTION":
                    section_name = self.rel_reader.get_section_name(symbol["st_shndx"])
                    symbol_offset = self.rel_sections_offsets_dict[section_name]
                else:
                    section_name = self.rel_reader.get_section_name(symbol["st_shndx"])
                    section_offset = self.rel_sections_offsets_dict[section_name]
                    symbol_offset = section_offset + self.rel_reader.get_symbol_offset(symbol.name)
                symbol_address = symbol_offset + self._get_base_address()

            instr_address = rel_text_section_offset + reloc["r_offset"] + self._get_base_address()
            self.exec_elf.stream.seek(instr_address - self._get_base_address())
            addend = reloc["r_addend"]

            if reloc["r_info_type"] in [ENUM_RELOC_TYPE_x64['R_X86_64_PC32'], ENUM_RELOC_TYPE_x64['R_X86_64_PLT32']]:
                rel_a_address = symbol_address + addend - instr_address
                self.exec_elf.stream.write(formatter32.packer.pack(rel_a_address))
            elif reloc["r_info_type"] in [ENUM_RELOC_TYPE_x64['R_X86_64_32'], ENUM_RELOC_TYPE_x64['R_X86_64_32S']]:
                rel_a_address = symbol_address + addend
                self.exec_elf.stream.write(formatter32.packer.pack(rel_a_address))
            elif reloc["r_inf_type"] == ENUM_RELOC_TYPE_x64['R_X86_64_64']:
                rel_a_address = symbol_address + addend
                self.exec_elf.stream.write(formatter64.packer.pack(rel_a_address))
