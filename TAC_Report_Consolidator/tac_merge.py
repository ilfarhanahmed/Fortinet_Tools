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

# --------------------------------------------------

archive = "tac_report.tar.gz"

with tarfile.open(archive, "r:*") as tar:
    for member in tar.getmembers():
        filename = PurePosixPath(member.name).name

        if filename.endswith(".log"):
            file_obj = tar.extractfile(member)

            if file_obj:
                data = file_obj.read()
                text = data.decode("utf-8", errors="replace")
                print (text)
                break



# -----
# MAIN
# ------
print("\n### " + (filename))