from elftools.construct import *
from elftools.elf.segments import Segment
from utils import *
from pwnlib.elf.elf import *
from rel_reader import *
from os import system

PAGE_SIZE = 0x1000

PF_EXECUTE = 0x1
PF_WRITE = 0x2
PF_READ = 0x4

LOAD_SEGMENT = "PT_LOAD"
PHDR_SEGMENT = "PT_PHDR"


class ExecManipulator:
    """
    ExecManipulator is responsible for reitrieving information from EXEC ELF file and also manipulating its content.
    """

    def __init__(self, orig_name, rel_name, output_name):
        system("cp  " + orig_name + " " + output_name)
        self.exec_elf = ELF(output_name)
        self.exec_elf.stream = open(output_name, "r+b")
        self.rel_reader = RelReader(rel_name)
        # dictionary that maps section name from REL file to its offset in EXEC file
        self.rel_sections_offsets_dict = dict()

    def __del__(self):
        self.exec_elf.stream.close()

    def update_segment_headers(self):
        """
        update_segment_headers is responsible for updating content of segment headers.
        Additionally, it reserves memory for incoming segment headers.
        Depending on the header's offset, size or address may be changed.
        This changes are based on the fact, whether header's segment contains segments header table.
        In the end it calls _update_sections_offsets function in order to update sectinons offsets as well.
        """
        # reserve memory for incoming segment headers
        make_gap(self.exec_elf.stream, self.exec_elf._segment_offset(self.exec_elf.num_segments()), PAGE_SIZE)
        self.exec_elf.header["e_shoff"] += PAGE_SIZE
        write_elf_header(self.exec_elf)

        first_segment = self.exec_elf.get_segment(0)
        if first_segment.header["p_type"] == "PT_PHDR":
            segment_table_size = first_segment["p_filesz"]
        else:
            segment_table_size = self.exec_elf._segment_offset(self.exec_elf.num_segments())
        for i, segment in enumerate(self.exec_elf.segments):
            if segment["p_offset"] < segment_table_size:
                segment.header["p_vaddr"] = max(segment.header["p_vaddr"] - PAGE_SIZE, 0)
                segment.header["p_paddr"] = max(segment.header["p_paddr"] - PAGE_SIZE, 0)
                if segment["p_type"] == "PT_LOAD":
                    segment.header["p_filesz"] += PAGE_SIZE
                    segment.header["p_memsz"] += PAGE_SIZE
            else:
                segment.header["p_offset"] += PAGE_SIZE
            write_segment(self.exec_elf, segment, i)
        self._update_sections_offsets()

    def generate_new_segments(self):
        """
        generate_new_segments combines rel_reader.fetch_rel_sections and _combine_sections functions in order to
        merge REL file sections with permissions R, RW, RWX, RX.
        In the end it calls _set_relocations in order to update relocations related to REL file.
        """
        fetch_rel_sections = self.rel_reader.fetch_rel_sections
        self._combine_sections(fetch_rel_sections(SHF_WRITE), PF_WRITE + PF_READ)
        self._combine_sections(fetch_rel_sections(SHF_EXECINSTR + SHF_WRITE), PF_EXECUTE + PF_WRITE + PF_READ)
        self._combine_sections(fetch_rel_sections(0), PF_READ)
        self._combine_sections(fetch_rel_sections(SHF_EXECINSTR), PF_EXECUTE + PF_READ)
        self._set_relocations()
        self._update_entry_address()

    def _update_sections_offsets(self):
        """
        update_sections_offsets changes sections offset values due to changes made in update_segment_headers function.
        """
        for i, section in enumerate(self.exec_elf.sections):
            if i == 0:
                continue
            section.header["sh_offset"] += PAGE_SIZE
            write_section(self.exec_elf, section, i)

    def _get_base_address(self):
        """
        _get_base_address retrieves address of beginning of the ELF file.
        """
        first_segment = self.exec_elf.get_segment(0)
        return first_segment.header["p_vaddr"] - first_segment.header["p_offset"]

    def _combine_sections(self, sections, segment_flags):
        """
        _combine_sections iterates over sections and writes their content to file (satisfying alignment requirements).
        Finally, creates new segment and adds its information to segment header table.
        Additionally, updates PHDR segment and ELf header.
        :param sections:      sections to be combined
        :param segment_flags: permissions of segment that is being created
        """
        if len(sections) == 0:
            return
        # aligning segment address
        self._align_stream(PAGE_SIZE)
        segment_offset = get_stream_size(self.exec_elf.stream)
        for section in sections:
            rel_section_offset = section.header["sh_offset"]
            section_size = section.header["sh_size"]
            # aligning section address
            self._align_stream(section.header["sh_addralign"])

            # saving offset of section in EXEC file
            exec_section_offset = get_stream_size(self.exec_elf.stream)
            self.rel_sections_offsets_dict[section.name] = exec_section_offset

            # reading section content
            section_content = self.rel_reader.get_stream_content(rel_section_offset, section_size)
            expand_stream(self.exec_elf.stream, section_size)
            # writing section content
            self.exec_elf.stream.seek(get_stream_size(self.exec_elf.stream) - section_size)
            self.exec_elf.stream.write(section_content)
        segment_headers = dict({
            "p_type": LOAD_SEGMENT,
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

        # updating PHDR segment header, if such exists
        phdr_segment = self.exec_elf.get_segment(0)
        if phdr_segment["p_type"] == PHDR_SEGMENT:
            phdr_segment.header["p_filesz"] += self.exec_elf.header["e_phentsize"]
            phdr_segment.header["p_memsz"] += self.exec_elf.header["e_phentsize"]
            write_segment(self.exec_elf, phdr_segment, 0)

        self.exec_elf.header["e_phnum"] += 1
        write_elf_header(self.exec_elf)

    def _update_entry_address(self):
        """
        _update_entry_address overwrites entry symbol address with _entry address added from REL, if present.
        """
        rel_text_section_offset = self.rel_sections_offsets_dict.get(".text", None)
        rel_entry_symbol_offset = self.rel_reader.get_symbol_offset("_start")
        if rel_text_section_offset is not None and rel_entry_symbol_offset is not None:
            entry_symbol_offset = rel_text_section_offset + rel_entry_symbol_offset
            self.exec_elf.header["e_entry"] = self._get_base_address() + entry_symbol_offset
            write_elf_header(self.exec_elf)

    def _align_stream(self, alignment):
        """
        align_stream expands stream so it satisfies given alignment.
        """
        remainder = (self._get_base_address() + get_stream_size(self.exec_elf.stream)) % alignment
        if remainder != 0:
            expand_stream(self.exec_elf.stream, alignment - remainder)

    def _set_relocations(self):
        """
        _set_relocations iterates over relocations, computes relocation's symbol address and inserts it into given
        address based on relocation type.
        """
        formatter32 = SLInt32("")
        formatter64 = SLInt64("")
        exec_symbol_table = self.exec_elf.get_section_by_name(".symtab")

        for reloc_section_name, reloc in self.rel_reader.get_relocations():
            symbol = self.rel_reader.get_symbol(reloc["r_info_sym"])
            if is_symbol_external(symbol):
                if symbol.name == "orig_start":
                    symbol_address = self.exec_elf.header["e_entry"]
                else:
                    symbol_address = exec_symbol_table.get_symbol_by_name(symbol.name)[0]["st_value"]
            else:
                section_name = self.rel_reader.get_section_name(symbol["st_shndx"])
                section_offset = self.rel_sections_offsets_dict[section_name]
                symbol_offset = section_offset + self.rel_reader.get_symbol_offset(symbol.name)
                symbol_address = symbol_offset + self._get_base_address()

            rel_section_offset = self.rel_sections_offsets_dict[reloc_section_name]
            instr_address = rel_section_offset + reloc["r_offset"] + self._get_base_address()
            self.exec_elf.stream.seek(instr_address - self._get_base_address())
            addend = reloc["r_addend"]

            if reloc["r_info_type"] in [ENUM_RELOC_TYPE_x64["R_X86_64_PC32"], ENUM_RELOC_TYPE_x64["R_X86_64_PLT32"]]:
                rel_a_address = symbol_address + addend - instr_address
                self.exec_elf.stream.write(formatter32.packer.pack(rel_a_address))
            elif reloc["r_info_type"] in [ENUM_RELOC_TYPE_x64["R_X86_64_32"], ENUM_RELOC_TYPE_x64["R_X86_64_32S"]]:
                rel_a_address = symbol_address + addend
                self.exec_elf.stream.write(formatter32.packer.pack(rel_a_address))
            elif reloc["r_info_type"] == ENUM_RELOC_TYPE_x64["R_X86_64_64"]:
                rel_a_address = symbol_address + addend
                self.exec_elf.stream.write(formatter64.packer.pack(rel_a_address))
