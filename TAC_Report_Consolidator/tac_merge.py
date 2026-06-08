#!/usr/bin/env python3

"""
TAC Report Consolidator
Author: Farhan Ahmed - www.farhan.ch
"""

import tarfile
import argparse
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
        # GUI TAC report files are always ending on .log, hence -4 will work below.
        filename = filename[:-4]
    if "_" in filename:
        # splitting the initial number part from filename.
        filename = filename.split("_", 1)[1]
    return filename

def command_num(filename):
    num_part = filename.split("_",1)[0]
    return int(num_part)

# Adding argparse to select the tar archive file
parser = argparse.ArgumentParser(
    description="TACMerge - merge FMG/FAZ GUI TAC Report"
)
# select an input file
parser.add_argument(
    "input_file",
    help="Path to TAC archive file"
)
# Output directory is optional, if not entered default is current dir.
parser.add_argument(
    "-o",
    "--output_dir",
    default=".",
    help="Output folder. Default is current directory."
)

args = parser.parse_args()

input_file = args.input_file
# converting to Path.
output_dir = Path(args.output_dir)
# If output_dir does not exist then create it.
# parents=True  => if parent folders (nested) do not exist then create them too.
# exist_ok=True => if folder already exist, do not crash.
output_dir.mkdir(parents=True, exist_ok=True)
# create output_file in the output_dir.
output_file = output_dir / f"TAC_Report_Merged_{timestamp()}.txt"

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
            # Skip if file cannot be opened or it's a folder
            if file_obj is None:
                continue
            # read the file, decode it to text and strip extra blank lines/spaces at the end.
            content = file_obj.read().decode("utf-8", errors="replace").rstrip()

            # Write to the output file.
            out.write("### " + command_name + "\n\n")
            out.write(content)
            out.write("\n\n\n")

print(f"Created: {output_file}")