#!/usr/bin/env python3
"""
TACMerge - FortiManager/FortiAnalyzer TAC Report Consolidator
==============================================================
Author: Farhan Ahmed - www.farhan.ch


What it does:
    1. Reads a TAC .tar.gz / .tgz / .tar archive directly
    2. Finds numbered command .log files, for example:
           0_diag debug reset.log
           6_get system status.log
           100_exe sql-report list-schedule all.log
    3. Writes one clean consolidated text file

Output format:
    ### diag debug reset
    <contents of 0_diag debug reset.log>

    ### get system status
    <contents of 6_get system status.log>

Important:
    This script does NOT extract files to disk.
    This avoids Windows filename problems with TAC files that contain characters
    like |, :, *, ?, <, >, etc.


Usage:
    python tacmerge.py tac_report.tar.gz

Optional:
    python tacmerge.py tac_report.tar.gz -o output_folder
"""

import argparse
import re
import sys
import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def filename_from_tar_path(tar_path):
    """
    Tar archives use / as the separator.
    This returns only the filename portion.
    """
    return PurePosixPath(tar_path).name


def is_numbered_command_log(member):
    """
    Include TAC command logs like:
        0_diag debug reset.log
        6_get system status.log
        100_exe sql-report list-schedule all.log

    This avoids unrelated system files such as:
        var/log/apache2/error_log
        apache2/conf/httpd.conf
        var/log/gui/remote_proxy.log
    """
    if not member.isfile():
        return False

    filename = filename_from_tar_path(member.name)

    if not filename.lower().endswith(".log"):
        return False

    return re.match(r"^\d+[_\s-].+\.log$", filename, re.IGNORECASE) is not None


def command_number(filename):
    """
    Return the leading TAC command number for sorting.
    """
    match = re.match(r"^(\d+)[_\s-]", filename)

    if match:
        return int(match.group(1))

    return 999999999


def command_name_from_filename(filename):
    """
    Convert:
        0_diag debug reset.log
    To:
        diag debug reset

    Convert:
        100_exe sql-report list-schedule all.log
    To:
        exe sql-report list-schedule all
    """
    name = filename.strip()

    if name.lower().endswith(".log"):
        name = name[:-4]

    name = re.sub(r"^\d+[_\s-]+", "", name)

    return name.strip()


def decode_bytes(data):
    """
    Decode log bytes into text.
    """
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue

    return data.decode("utf-8", errors="replace")


def tacmerge(input_file, output_dir="."):
    input_file = Path(input_file).resolve()
    output_dir = Path(output_dir).resolve()

    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if not tarfile.is_tarfile(input_file):
        raise ValueError("Input file must be a .tar, .tar.gz, or .tgz archive")

    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"TACMerge_Report_{timestamp()}.txt"

    with tarfile.open(input_file, "r:*") as tar:
        members = [
            member for member in tar.getmembers()
            if is_numbered_command_log(member)
        ]

        members.sort(
            key=lambda member: (
                command_number(filename_from_tar_path(member.name)),
                filename_from_tar_path(member.name).lower()
            )
        )

        with open(output_file, "w", encoding="utf-8", errors="replace") as out:
            for index, member in enumerate(members):
                filename = filename_from_tar_path(member.name)
                command_name = command_name_from_filename(filename)

                extracted_file = tar.extractfile(member)

                if extracted_file is None:
                    content = ""
                else:
                    content = decode_bytes(extracted_file.read()).rstrip()

                if index > 0:
                    out.write("\n\n")

                out.write(f"### {command_name}\n")

                if content:
                    out.write(content)
                    out.write("\n")

    return output_file, len(members)


def main():
    parser = argparse.ArgumentParser(
        description="TACMerge - merge numbered Fortinet TAC command .log files into one clean report."
    )

    parser.add_argument(
        "input_file",
        help="Path to TAC archive, for example: tac_report.tar.gz"
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Output folder. Default: current folder."
    )

    args = parser.parse_args()

    try:
        output_file, total = tacmerge(args.input_file, args.output_dir)

        print("TACMerge completed")
        print(f"Command log files merged: {total}")
        print(f"Output file: {output_file}")

        return 0

    except Exception as error:
        print(f"TACMerge failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
