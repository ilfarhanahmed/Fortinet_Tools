#!/usr/bin/env python3

"""
TAC Report Consolidator
Author: Farhan Ahmed - www.farhan.ch
"""
# Header
# -------
print("TACMerge")
print("FortiManager/FortiAnalyzer GUI TAC report command-log merger")
print("============================")

filename = "6_get system status.log"
# print(filename[2:])

def command_name_from_filename(filename):
    real_name = filename[:-4]  # GUI TAC report files are always ending on .log, hence -4 will work.
    command_name = real_name.split("_", 1) # splitting the initial number part from filename.
    return command_name[1] # that is the second part of split which is the command.


from pathlib import Path

# Read TAC Report
# -----------------
file1 = "6_get system status.log"
file_path = Path("6_get system status.log")
content1 = file_path.read_text(encoding="utf-8")

file2 = "7_get system global.log"
file_path2 = Path("7_get system global.log")
content2 = file_path2.read_text(encoding="utf-8")

# Create consolidated file
# -------------------------
output_file = Path("Merged_TAC_Report.txt")

with open(output_file, "w", encoding="utf-8") as out:
    out.write("### " + command_name_from_filename(file1) + "\n")
    out.write(content1 + "\n")
    out.write("\n### " + command_name_from_filename(file2) + "\n")
    out.write(content2 + "\n")


# -----
# MAIN
# ------
print("### " + command_name_from_filename(filename))