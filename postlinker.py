from pwnlib.elf.elf import *
from utils import *
import shutil

shutil.copyfile("z1-example/exec-orig", "tmp")
elf = ELF("tmp")
elf.stream = open("tmp", "r+b")

# changing segment offset to 0x2137
segment_num = 2
segment = elf.segments[segment_num]
segment.header["p_offset"] = 0x2137
segment_offset = elf._segment_offset(segment_num)
elf.stream.seek(segment_offset)
elf.stream.write(generate_phdr_string(elf, segment))

# changing start address to 0x2137
elf.header["e_entry"] = 0x2137
elf.stream.seek(0)
elf.stream.write(generate_edhr_string(elf))
elf.stream.seek(segment_offset)

# changing section offset to 0x2137
section_num = 1
section = elf.sections[section_num]
section.header["sh_offset"] = 0x2137
section_offset = elf._section_offset(section_num)
elf.stream.seek(section_offset)
elf.stream.write(generate_shdr_string(elf, section))