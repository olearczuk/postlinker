from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

SHF_ALLOC = 0x2
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4


class RelReader:
    def __init__(self, rel_name):
        self.rel_elf = ELFFile(open(rel_name, "rb"))
        self.rel_symbol_table = self.rel_elf.get_section_by_name(".symtab")

    def __del__(self):
        self.rel_elf.stream.close()

    def fetch_rel_sections(self, expected_flags):
        """
        fetch_rel_sections returns SHF_ALLOC sections that satisfy given expected flag and are not empty.
        :param expected_flags: combination of SHF_WRITE and SHF_EXECINSTR
        """
        sections = []
        for section in self.rel_elf.iter_sections():
            flags = section.header["sh_flags"]
            section_size = section.header["sh_size"]
            if flags & SHF_ALLOC and section_size > 0:
                cur_flags = flags & (SHF_WRITE + SHF_EXECINSTR)
                if cur_flags == expected_flags:
                    sections.append(section)
        return sections

    def get_relocations(self):
        """
        get_relocations returns list of pairs (relocation's section name, relocation).
        """
        relocations = []
        for section in self.rel_elf.iter_sections():
            if isinstance(section, RelocationSection):
                for relocation in section.iter_relocations():
                    relocations.append((section.name[5:], relocation))
        return relocations

    def get_stream_content(self, offset, size):
        """
        returns content of stream based on offset and size.
        :param offset: beginning of content
        :param size:   content size
        """
        self.rel_elf.stream.seek(offset)
        return self.rel_elf.stream.read(size)

    def get_symbol(self, index):
        return self.rel_symbol_table.get_symbol(index)

    def get_section_name(self, index):
        return self.rel_elf.get_section(index).name

    def get_symbol_offset(self, symbol_name):
        """
        get_symbol_offset returns given symbol offset or None, if such symbol does not exist.
        """
        symbols = self.rel_symbol_table.get_symbol_by_name(symbol_name)
        if symbols is None:
            return None
        symbol = symbols[0]
        return symbol["st_value"]
