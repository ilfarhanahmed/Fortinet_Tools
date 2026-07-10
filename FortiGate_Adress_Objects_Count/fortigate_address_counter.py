#!/usr/bin/env python3
"""
FortiGate Address and Address Group Analyzer
by Farhan Ahmed | www.farhan.ch

Features:
- Opens FortiGate configuration, log, TAC report, .gz, .tar.gz, or .tgz files
- Counts explicit firewall.address objects by VDOM
- Counts firewall.addrgrp objects by VDOM
- Shows the unique member count for every address group
- Detects duplicate members within the same group
- Detects objects used in multiple groups
- Filters an address object and shows its group memberships
- Displays results on screen only; no export
"""

from __future__ import annotations

import gzip
import io
import re
import shlex
import tarfile
import tkinter as tk
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText


APP_NAME = "FortiGate Address Group Analyzer v3"

CONFIG_RE = re.compile(r"^\s*config\s+(.+?)\s*$", re.IGNORECASE)
EDIT_RE = re.compile(r'^\s*edit\s+(?:"([^"]*)"|(\S+))\s*$', re.IGNORECASE)
NEXT_RE = re.compile(r"^\s*next\s*$", re.IGNORECASE)
END_RE = re.compile(r"^\s*end\s*$", re.IGNORECASE)
SET_MEMBER_RE = re.compile(r"^\s*set\s+member(?:\s+(.*))?$", re.IGNORECASE)
APPEND_MEMBER_RE = re.compile(r"^\s*append\s+member(?:\s+(.*))?$", re.IGNORECASE)
UNSET_MEMBER_RE = re.compile(r"^\s*unset\s+member\s*$", re.IGNORECASE)
PROMPT_VDOM_RE = re.compile(r"^\S+\s+\(([^)]+)\)\s+[#$]\s*(?:.*)?$")


@dataclass
class ParsedData:
    addresses: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    groups: dict[str, dict[str, list[str]]] = field(
        default_factory=lambda: defaultdict(dict)
    )
    selected_file: str = ""
    source_count: int = 0
    matching_source_count: int = 0


def normalize_config_name(name: str) -> str:
    return " ".join(name.strip().lower().split())


def parse_cli_values(value: str | None) -> list[str]:
    if not value:
        return []

    try:
        return shlex.split(value, posix=True)
    except ValueError:
        values: list[str] = []
        for quoted, unquoted in re.findall(r'"([^"]*)"|(\S+)', value):
            item = quoted or unquoted
            if item:
                values.append(item)
        return values


def read_text_sources(path: Path) -> list[tuple[str, str]]:
    lower_name = path.name.lower()

    if lower_name.endswith((".tar.gz", ".tgz")):
        results: list[tuple[str, str]] = []

        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue

                extracted = archive.extractfile(member)
                if extracted is None:
                    continue

                data = extracted.read()

                if b"\x00" in data[:4096]:
                    continue

                results.append(
                    (member.name, data.decode("utf-8", errors="replace"))
                )

        if not results:
            raise ValueError("No readable text files were found in the archive.")

        return results

    if lower_name.endswith(".gz"):
        with gzip.open(path, "rb") as handle:
            data = handle.read()

        return [(path.name, data.decode("utf-8", errors="replace"))]

    data = path.read_bytes()

    if b"\x00" in data[:4096]:
        raise ValueError(
            "The selected file appears to be binary rather than a text file."
        )

    return [(path.name, data.decode("utf-8", errors="replace"))]


def parse_source(text: str) -> tuple[
    dict[str, set[str]],
    dict[str, dict[str, list[str]]],
]:
    addresses: dict[str, set[str]] = defaultdict(set)
    groups: dict[str, dict[str, list[str]]] = defaultdict(dict)

    config_stack: list[str] = []
    current_vdom = "unknown"
    current_group: str | None = None

    for raw_line in io.StringIO(text):
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()

        if not stripped:
            continue

        prompt_match = PROMPT_VDOM_RE.match(stripped)
        if prompt_match:
            prompt_vdom = prompt_match.group(1).strip()
            if prompt_vdom and prompt_vdom.lower() != "global":
                current_vdom = prompt_vdom
            continue

        config_match = CONFIG_RE.match(line)
        if config_match:
            config_stack.append(
                normalize_config_name(config_match.group(1))
            )
            continue

        if END_RE.match(line):
            if config_stack:
                ended = config_stack.pop()
                if ended == "firewall addrgrp":
                    current_group = None
            continue

        if NEXT_RE.match(line):
            if config_stack and config_stack[-1] == "firewall addrgrp":
                current_group = None
            continue

        edit_match = EDIT_RE.match(line)
        if edit_match:
            object_name = (
                edit_match.group(1) or edit_match.group(2) or ""
            ).strip()

            if config_stack == ["vdom"]:
                current_vdom = object_name.split("/", 1)[0] or "unknown"
                continue

            if config_stack and config_stack[-1] == "firewall address":
                addresses[current_vdom].add(object_name)
                continue

            if config_stack and config_stack[-1] == "firewall addrgrp":
                current_group = object_name
                groups[current_vdom].setdefault(current_group, [])
                continue

        if (
            current_group is not None
            and config_stack
            and config_stack[-1] == "firewall addrgrp"
        ):
            set_match = SET_MEMBER_RE.match(line)
            if set_match:
                groups[current_vdom][current_group] = parse_cli_values(
                    set_match.group(1)
                )
                continue

            append_match = APPEND_MEMBER_RE.match(line)
            if append_match:
                groups[current_vdom][current_group].extend(
                    parse_cli_values(append_match.group(1))
                )
                continue

            if UNSET_MEMBER_RE.match(line):
                groups[current_vdom][current_group] = []

    return addresses, groups


def load_and_parse(path: Path) -> ParsedData:
    sources = read_text_sources(path)

    result = ParsedData(
        selected_file=str(path),
        source_count=len(sources),
    )

    for _, text in sources:
        source_addresses, source_groups = parse_source(text)

        if source_addresses or source_groups:
            result.matching_source_count += 1

        for vdom, names in source_addresses.items():
            result.addresses[vdom].update(names)

        for vdom, vdom_groups in source_groups.items():
            for group_name, members in vdom_groups.items():
                existing = result.groups[vdom].get(group_name)

                if existing is None:
                    result.groups[vdom][group_name] = list(members)
                elif not existing and members:
                    result.groups[vdom][group_name] = list(members)
                elif existing != members and members:
                    # Preserve differing fragments in TAC reports.
                    result.groups[vdom][group_name].extend(members)

    return result


def build_membership_index(
    data: ParsedData,
) -> dict[tuple[str, str], list[str]]:
    index: dict[tuple[str, str], list[str]] = defaultdict(list)

    for vdom, groups in data.groups.items():
        for group_name, members in groups.items():
            for member_name in set(members):
                index[(vdom, member_name)].append(group_name)

    for group_names in index.values():
        group_names.sort(key=str.lower)

    return index


def format_full_report(data: ParsedData) -> str:
    vdoms = sorted(
        set(data.addresses) | set(data.groups),
        key=str.lower,
    )

    total_addresses = sum(len(items) for items in data.addresses.values())
    total_groups = sum(len(items) for items in data.groups.values())

    lines: list[str] = []
    lines.append(APP_NAME)
    lines.append(f"File: {data.selected_file}")

    if data.source_count > 1:
        lines.append(
            f"Archive text files scanned: {data.source_count} "
            f"({data.matching_source_count} contained address configuration)"
        )

    lines.append("")
    lines.append("SUMMARY BY VDOM")
    lines.append("")
    lines.append(
        f"{'VDOM':<38}"
        f"{'Addresses':>12}"
        f"{'Address groups':>16}"
    )
    lines.append("-" * 66)

    for vdom in vdoms:
        lines.append(
            f"{vdom:<38}"
            f"{len(data.addresses.get(vdom, set())):>12,}"
            f"{len(data.groups.get(vdom, {})):>16,}"
        )

    lines.append("-" * 66)
    lines.append(
        f"{'TOTAL':<38}"
        f"{total_addresses:>12,}"
        f"{total_groups:>16,}"
    )

    lines.append("")
    lines.append("=" * 90)
    lines.append("ADDRESS GROUP MEMBER COUNTS")
    lines.append("=" * 90)

    if not data.groups:
        lines.append("")
        lines.append("No firewall.addrgrp configuration was found.")
    else:
        for vdom in sorted(data.groups, key=str.lower):
            groups = data.groups[vdom]

            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append("-" * 90)
            lines.append(
                f"{'Address group':<62}"
                f"{'Unique members':>15}"
                f"{'Duplicate entries':>18}"
            )

            for group_name in sorted(groups, key=str.lower):
                members = groups[group_name]
                counts = Counter(members)
                duplicate_entries = sum(
                    count - 1 for count in counts.values() if count > 1
                )

                lines.append(
                    f"{group_name:<62}"
                    f"{len(counts):>15,}"
                    f"{duplicate_entries:>18,}"
                )

    lines.append("")
    lines.append("=" * 90)
    lines.append("DUPLICATE MEMBERS WITHIN THE SAME GROUP")
    lines.append("=" * 90)

    duplicate_found = False

    for vdom in sorted(data.groups, key=str.lower):
        for group_name in sorted(data.groups[vdom], key=str.lower):
            duplicate_members = {
                member: count
                for member, count in Counter(
                    data.groups[vdom][group_name]
                ).items()
                if count > 1
            }

            if not duplicate_members:
                continue

            duplicate_found = True
            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append(f"Group: {group_name}")

            for member, count in sorted(
                duplicate_members.items(),
                key=lambda item: item[0].lower(),
            ):
                lines.append(f"  {member} — appears {count} times")

    if not duplicate_found:
        lines.append("")
        lines.append("No duplicate members were found within any group.")

    lines.append("")
    lines.append("=" * 90)
    lines.append("OBJECTS USED IN MULTIPLE GROUPS")
    lines.append("=" * 90)

    membership_index = build_membership_index(data)
    reused = [
        (vdom, object_name, group_names)
        for (vdom, object_name), group_names in membership_index.items()
        if len(group_names) > 1
    ]

    if not reused:
        lines.append("")
        lines.append(
            "No object was found in multiple address groups within the same VDOM."
        )
    else:
        lines.append("")
        lines.append(f"Objects used in multiple groups: {len(reused):,}")

        for vdom, object_name, group_names in sorted(
            reused,
            key=lambda item: (item[0].lower(), item[1].lower()),
        ):
            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append(f"Object: {object_name}")
            lines.append(f"Group count: {len(group_names):,}")
            lines.append("Groups: " + ", ".join(group_names))

    lines.append("")
    lines.append("=" * 90)
    lines.append("NOTES")
    lines.append("=" * 90)
    lines.append(
        "• Address totals count explicit config firewall address entries."
    )
    lines.append(
        "• Address-group totals count explicit config firewall addrgrp entries."
    )
    lines.append(
        "• Duplicate checking is performed inside each individual group."
    )
    lines.append(
        "• Multi-group usage is evaluated separately inside each VDOM."
    )

    return "\n".join(lines)


def format_filter_results(data: ParsedData, query: str) -> str:
    query = query.strip()

    if not query:
        return "Enter an address object name or part of a name."

    query_lower = query.lower()
    membership_index = build_membership_index(data)
    matches: set[tuple[str, str]] = set()

    for vdom, objects in data.addresses.items():
        for object_name in objects:
            if query_lower in object_name.lower():
                matches.add((vdom, object_name))

    for vdom, groups in data.groups.items():
        for members in groups.values():
            for object_name in members:
                if query_lower in object_name.lower():
                    matches.add((vdom, object_name))

    lines: list[str] = []
    lines.append(APP_NAME)
    lines.append(f'FILTER: "{query}"')
    lines.append("=" * 90)

    if not matches:
        lines.append("")
        lines.append("No matching address object or group member was found.")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"Matches: {len(matches):,}")

    for vdom, object_name in sorted(
        matches,
        key=lambda item: (item[0].lower(), item[1].lower()),
    ):
        groups = membership_index.get((vdom, object_name), [])
        explicitly_defined = object_name in data.addresses.get(vdom, set())

        lines.append("")
        lines.append(f"VDOM: {vdom}")
        lines.append(f"Object: {object_name}")
        lines.append(
            "Explicit firewall.address object: "
            + ("Yes" if explicitly_defined else "No / not found in file")
        )
        lines.append(f"Group membership count: {len(groups):,}")

        if groups:
            for group_name in groups:
                lines.append(f"  - {group_name}")
        else:
            lines.append("  Not used in any address group found in the file.")

    return "\n".join(lines)


class AnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1180x800")
        self.root.minsize(850, 550)

        self.data: ParsedData | None = None

        toolbar = tk.Frame(root, padx=10, pady=10)
        toolbar.pack(fill="x")

        tk.Button(
            toolbar,
            text="Load FortiGate File",
            command=self.load_file,
            padx=14,
            pady=7,
        ).pack(side="left")

        tk.Button(
            toolbar,
            text="Show Full Report",
            command=self.show_full_report,
            padx=14,
            pady=7,
        ).pack(side="left", padx=(8, 0))

        filter_frame = tk.LabelFrame(
            root,
            text="Filter address object and show group membership",
            padx=10,
            pady=8,
        )
        filter_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.filter_value = tk.StringVar()

        filter_entry = tk.Entry(
            filter_frame,
            textvariable=self.filter_value,
            font=("Consolas", 10),
        )
        filter_entry.pack(side="left", fill="x", expand=True)
        filter_entry.bind("<Return>", lambda _event: self.apply_filter())

        tk.Button(
            filter_frame,
            text="Filter",
            command=self.apply_filter,
            padx=14,
        ).pack(side="left", padx=(8, 0))

        tk.Button(
            filter_frame,
            text="Clear Filter",
            command=self.clear_filter,
            padx=14,
        ).pack(side="left", padx=(8, 0))

        self.output = ScrolledText(
            root,
            wrap="none",
            font=("Consolas", 10),
            padx=10,
            pady=10,
        )
        self.output.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10),
        )

        self.set_output(
            f"{APP_NAME}\n\n"
            "Select a FortiGate configuration, log, TAC report, "
            ".gz, .tar.gz, or .tgz file."
        )

    def set_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text)
        self.output.configure(state="disabled")

    def load_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select FortiGate file",
            filetypes=[
                (
                    "FortiGate files",
                    "*.conf *.txt *.log *.out *.gz *.tgz",
                ),
                ("Configuration files", "*.conf"),
                ("Text and log files", "*.txt *.log *.out"),
                ("Compressed files", "*.gz *.tgz"),
                ("All files", "*.*"),
            ],
        )

        if not filename:
            return

        try:
            self.data = load_and_parse(Path(filename))
            self.filter_value.set("")
            self.show_full_report()
        except Exception as exc:
            messagebox.showerror(
                "Unable to analyze file",
                str(exc),
            )

    def show_full_report(self) -> None:
        if self.data is None:
            self.set_output("Load a FortiGate file first.")
            return

        self.set_output(format_full_report(self.data))

    def apply_filter(self) -> None:
        if self.data is None:
            messagebox.showinfo(
                "No file loaded",
                "Load a FortiGate file first.",
            )
            return

        self.set_output(
            format_filter_results(
                self.data,
                self.filter_value.get(),
            )
        )

    def clear_filter(self) -> None:
        self.filter_value.set("")
        self.show_full_report()


def main() -> int:
    root = tk.Tk()
    AnalyzerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
