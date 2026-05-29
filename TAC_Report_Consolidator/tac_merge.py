#!/usr/bin/env python3

"""
TAC Report Consolidator
Author: Farhan Ahmed - www.farhan.ch
"""

import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath

# Header
# -------
print("TACMerge")
print("FortiManager/FortiAnalyzer GUI TAC report command-log merger")
print("============================")


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def command_name_from_filename(filename):
    if filename.endswith(".log"):
        filename = filename[:-4]  # GUI TAC report files are always ending on .log, hence -4 will work.
    if "_" in filename:
        filename = filename.split("_", 1)[1] # splitting the initial number part from filename.
    return filename

input_file = "tac_report.tar.gz"
output_file = Path(f"TAC_Report_Merged_{timestamp()}.txt")

with tarfile.open(input_file, "r:*") as tar:
    with open(output_file, "w", encoding="utf-8") as out:
        for member in tar.getmembers():
            filename = PurePosixPath(member.name).name

            # If file name is NOT ending with .log then skip it.
            if not filename.endswith(".log"):
                continue

            # Stripping the extension and number prefix.
            command_name = command_name_from_filename(filename)

            # Read content of the TAR members i.e. log files.
            file_obj = tar.extractfile(member)
            # Skip if file cannot be opened or its a folder
            if file_obj is None:
                continue
            # read the file, decode it to text and strip extra blank lines/spaces at the end.
            content = file_obj.read().decode("utf-8", errors="replace").rstrip()

            # Write to the output file.
            out.write("### " + command_name + "\n\n")
            out.write(content)
            out.write("\n\n\n")

print(f"Created: {output_file}")


# -----
# MAIN
# ------
print("\n### " + (filename))