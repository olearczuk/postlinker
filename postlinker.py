#!/usr/bin/python3
from exec_manipulator import ExecManipulator
import sys
import os

if len(sys.argv) < 4:
    print("usage: ./postlinker ET_EXEC> <ET_REL> <output ET_EXEC>")
    exit(1)
exec_file = sys.argv[1]
rel_file = sys.argv[2]
exec_output = sys.argv[3]

exec_manipulator = ExecManipulator(exec_file, rel_file, exec_output)
exec_manipulator.update_segments_offsets()
exec_manipulator.update_sections_offsets()
exec_manipulator.generate_new_segments()

os.system("chmod u+x " + exec_output)
