from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

SHF_ALLOC = 0x2
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4


def is_symbol_extern(symbol):
    return symbol["st_shndx"] == "SHN_UNDEF"


class RelReader:
    def __init__(self, rel_name):
        self.rel_elf = ELFFile(open(rel_name, "rb"))
        self.rel_symbol_table = self.rel_elf.get_section_by_name(".symtab")

    def fetch_rel_sections(self, expected_flags):
        sections = []
        section_index = 0
        for section in self.rel_elf.iter_sections():
            flags = section.header["sh_flags"]
            section_size = section.header["sh_size"]
            if flags & SHF_ALLOC and section_size > 0:
                cur_flags = flags & (SHF_WRITE + SHF_EXECINSTR)
                if cur_flags == expected_flags:
                    sections.append(section)
            section_index += 1
        return sections

    def get_relocations(self):
        reladyn_name = '.rela.text'
        reladyn = self.rel_elf.get_section_by_name(reladyn_name)
        if not isinstance(reladyn, RelocationSection):
            return []
        return reladyn.iter_relocations()

    def get_stream_content(self, offset, size):
        self.rel_elf.stream.seek(offset)
        return self.rel_elf.stream.read(size)

    def get_symbol(self, index):
        return self.rel_symbol_table.get_symbol(index)

    def get_section_name(self, index):
        return self.rel_elf.get_section(index).name

    def get_symbol_offset(self, symbol_name):
        symbols = self.rel_symbol_table.get_symbol_by_name(symbol_name)
        if symbols is None:
            return -1
        symbol = symbols[0]
        return symbol["st_value"]
