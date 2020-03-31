from elf_manipulator import *

if __name__ == "__main__":
    exec_file = "z1-example/exec-orig"
    rel_file = "z1-example/rel.o"
    exec_output = "tmp"

    elf_manipulator = ElfManipulator(exec_file, exec_output)

    elf_manipulator.update_segments_offsets()
    elf_manipulator.update_sections_offsets()

    segment = elf_manipulator.elf.get_segment(1)
    elf_manipulator.add_new_segment(segment)
