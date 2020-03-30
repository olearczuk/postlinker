from io import SEEK_END
from elftools.elf.enums import *


def generate_phdr_string(elf, segment):
    """
    generate_phdr_string generates bytes representation of given segment.
    :param elf:
    :param segment:
    :return:
    """
    p_type_dict = ENUM_P_TYPE_BASE
    if elf["e_machine"] == 'EM_ARM':
        p_type_dict = ENUM_P_TYPE_ARM
    elif elf["e_machine"] == 'EM_AARCH64':
        p_type_dict = ENUM_P_TYPE_AARCH64
    elif elf["e_machine"] == 'EM_MIPS':
        p_type_dict = ENUM_P_TYPE_MIPS

    s = elf.structs.Elf_Phdr.subcons[0].subcon.packer.pack(p_type_dict[segment.header["p_type"]])
    header_keys = list(segment.header)
    for i, key in enumerate(header_keys[1:]):
        s += elf.structs.Elf_Phdr.subcons[i+1].packer.pack(segment.header[key])
    return s


def generate_edhr_string(elf):
    """
    generate_edhr_string generates bytes representation of given ELF header.
    :param elf:
    :return:
    """
    e_ident_struct = elf.structs.Elf_Ehdr.subcons[0]
    e_ident_dict = elf["e_ident"]
    s = b""
    for ei_mag_elem in e_ident_dict["EI_MAG"]:
        s += e_ident_struct.subcons[0].subcon.packer.pack(ei_mag_elem)
    s += e_ident_struct.subcons[1].subcon.packer.pack(ENUM_EI_CLASS[e_ident_dict["EI_CLASS"]])
    s += e_ident_struct.subcons[2].subcon.packer.pack(ENUM_EI_DATA[e_ident_dict["EI_DATA"]])
    s += e_ident_struct.subcons[2].subcon.packer.pack(ENUM_E_VERSION[e_ident_dict["EI_VERSION"]])
    s += e_ident_struct.subcons[2].subcon.packer.pack(ENUM_EI_OSABI[e_ident_dict["EI_OSABI"]])
    s += e_ident_struct.subcons[2].subcon.packer.pack(e_ident_dict["EI_ABIVERSION"])
    s += bytes(7)

    s += elf.structs.Elf_Ehdr.subcons[1].subcon.packer.pack(ENUM_E_TYPE[elf.header["e_type"]])
    s += elf.structs.Elf_Ehdr.subcons[2].subcon.packer.pack(ENUM_E_MACHINE[elf.header["e_machine"]])
    s += elf.structs.Elf_Ehdr.subcons[3].subcon.packer.pack(ENUM_E_VERSION[elf.header["e_version"]])

    header_keys = list(elf.header)
    for i, key in enumerate(header_keys[4:]):
        s += elf.structs.Elf_Ehdr.subcons[i+4].packer.pack(elf.header[key])
    return s


def generate_shdr_string(elf, section):
    """
    generate_shdr_string generates bytes representation of given section.
    :param elf:
    :param section:
    :return:
    """
    sh_type_dict = ENUM_SH_TYPE_BASE
    if elf["e_machine"] == 'EM_ARM':
        sh_type_dict = ENUM_SH_TYPE_ARM
    elif elf["e_machine"] == 'EM_X86_64':
        sh_type_dict = ENUM_SH_TYPE_AMD64
    elif elf["e_machine"] == 'EM_MIPS':
        sh_type_dict = ENUM_SH_TYPE_MIPS

    s = elf.structs.Elf_Shdr.subcons[0].packer.pack(section.header["sh_name"])
    s += elf.structs.Elf_Shdr.subcons[1].subcon.packer.pack(sh_type_dict[section.header["sh_type"]])

    header_keys = list(section.header)
    for i, key in enumerate(header_keys[2:]):
        s += elf.structs.Elf_Shdr.subcons[i + 2].packer.pack(section.header[key])
    return s


def make_gap(elf, offset, size):
    """
    make_gap moves creates new space for writing, pushing current content aside.
    TODO - currently offsets are not fixed after creating the gap
    :param elf:
    :param offset:
    :param size:
    :return:
    """
    elf.stream.seek(offset)
    content = elf.stream.read()

    elf.stream.seek(0, SEEK_END)
    pos = elf.stream.tell()
    print(pos)
    elf.stream.truncate(pos + size)

    elf.stream.seek(offset+size)
    elf.stream.write(content)

    gap = bytes(size)
    elf.stream.seek(offset)
    elf.stream.write(gap)
