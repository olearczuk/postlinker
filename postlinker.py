#!/usr/bin/python3
from elf_manipulator import *
import sys
import os

if len(sys.argv) < 4:
    print("usage: ./postlinker ET_EXEC> <ET_REL> <output ET_EXEC>")
    exit(1)
exec_file = sys.argv[1]
rel_file = sys.argv[2]
exec_output = sys.argv[3]

exec_manipulator = ElfManipulator(exec_file, rel_file, exec_output)

exec_manipulator.update_segments_offsets()
exec_manipulator.update_sections_offsets()

exec_manipulator.fetch_rel_sections()

exec_manipulator.combine_sections(exec_manipulator.write_sections, PF_WRITE + PF_READ)
exec_manipulator.combine_sections(exec_manipulator.exec_write_sections, PF_EXECUTE + PF_WRITE + PF_READ)
exec_manipulator.combine_sections(exec_manipulator.other_sections, PF_READ)
exec_manipulator.combine_sections(exec_manipulator.exec_sections, PF_EXECUTE + PF_READ)

os.system("chmod u+x " + exec_output)
