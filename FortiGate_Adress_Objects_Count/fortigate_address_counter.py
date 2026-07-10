#!/usr/bin/env python3
"""
FortiGate Address and Address Group Analyzer v5
by Farhan Ahmed | www.farhan.ch

Features:
- Opens FortiGate configuration, log, TAC report, .gz, .tar.gz, or .tgz files
- Counts explicit firewall.address objects by VDOM
- Counts firewall.addrgrp objects by VDOM
- Shows direct members, nested groups, and effective leaf addresses per group
- Detects duplicate direct members within the same group
- Detects objects used directly or indirectly in multiple groups
- Detects circular nested-group references
- Filters address objects or address groups
- Shows direct and inherited group memberships
- Shows the full configuration block of matched address objects and groups
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


APP_NAME = "FortiGate Address Group Analyzer v5"

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
    address_configs: dict[tuple[str, str], str] = field(default_factory=dict)
    group_configs: dict[tuple[str, str], str] = field(default_factory=dict)
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


def format_object_block(
    table_name: str,
    object_name: str,
    body_lines: list[str],
) -> str:
    lines = [f"config {table_name}", f'    edit "{object_name}"']
    lines.extend(body_lines)
    lines.append("    next")
    lines.append("end")
    return "\n".join(lines)


def parse_source(
    text: str,
) -> tuple[
    dict[str, set[str]],
    dict[str, dict[str, list[str]]],
    dict[tuple[str, str], str],
    dict[tuple[str, str], str],
]:
    addresses: dict[str, set[str]] = defaultdict(set)
    groups: dict[str, dict[str, list[str]]] = defaultdict(dict)
    address_configs: dict[tuple[str, str], str] = {}
    group_configs: dict[tuple[str, str], str] = {}

    config_stack: list[str] = []
    current_vdom = "unknown"

    current_object_name: str | None = None
    current_object_table: str | None = None
    current_object_body: list[str] = []

    def save_current_object() -> None:
        nonlocal current_object_name, current_object_table, current_object_body

        if current_object_name is None or current_object_table is None:
            return

        block = format_object_block(
            current_object_table,
            current_object_name,
            current_object_body,
        )

        key = (current_vdom, current_object_name)

        if current_object_table == "firewall address":
            address_configs.setdefault(key, block)
        elif current_object_table == "firewall addrgrp":
            group_configs.setdefault(key, block)

        current_object_name = None
        current_object_table = None
        current_object_body = []

    for raw_line in io.StringIO(text):
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()

        if not stripped:
            if current_object_name is not None:
                current_object_body.append(line)
            continue

        prompt_match = PROMPT_VDOM_RE.match(stripped)
        if prompt_match:
            save_current_object()
            prompt_vdom = prompt_match.group(1).strip()
            if prompt_vdom and prompt_vdom.lower() != "global":
                current_vdom = prompt_vdom
            continue

        config_match = CONFIG_RE.match(line)
        if config_match:
            config_stack.append(normalize_config_name(config_match.group(1)))
            continue

        if END_RE.match(line):
            save_current_object()
            if config_stack:
                config_stack.pop()
            continue

        if NEXT_RE.match(line):
            save_current_object()
            continue

        edit_match = EDIT_RE.match(line)
        if edit_match:
            object_name = (
                edit_match.group(1) or edit_match.group(2) or ""
            ).strip()

            if config_stack == ["vdom"]:
                save_current_object()
                current_vdom = object_name.split("/", 1)[0] or "unknown"
                continue

            if config_stack and config_stack[-1] == "firewall address":
                save_current_object()
                current_object_name = object_name
                current_object_table = "firewall address"
                current_object_body = []
                addresses[current_vdom].add(object_name)
                continue

            if config_stack and config_stack[-1] == "firewall addrgrp":
                save_current_object()
                current_object_name = object_name
                current_object_table = "firewall addrgrp"
                current_object_body = []
                groups[current_vdom].setdefault(object_name, [])
                continue

        if current_object_name is not None:
            current_object_body.append(line)

            if current_object_table == "firewall addrgrp":
                set_match = SET_MEMBER_RE.match(line)
                if set_match:
                    groups[current_vdom][current_object_name] = parse_cli_values(
                        set_match.group(1)
                    )
                    continue

                append_match = APPEND_MEMBER_RE.match(line)
                if append_match:
                    groups[current_vdom][current_object_name].extend(
                        parse_cli_values(append_match.group(1))
                    )
                    continue

                if UNSET_MEMBER_RE.match(line):
                    groups[current_vdom][current_object_name] = []

    save_current_object()

    return addresses, groups, address_configs, group_configs


def load_and_parse(path: Path) -> ParsedData:
    sources = read_text_sources(path)

    result = ParsedData(
        selected_file=str(path),
        source_count=len(sources),
    )

    for _, text in sources:
        (
            source_addresses,
            source_groups,
            source_address_configs,
            source_group_configs,
        ) = parse_source(text)

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
                    result.groups[vdom][group_name].extend(members)

        for key, config in source_address_configs.items():
            result.address_configs.setdefault(key, config)

        for key, config in source_group_configs.items():
            result.group_configs.setdefault(key, config)

    return result


def direct_membership_index(
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


def resolve_group(
    vdom: str,
    group_name: str,
    groups: dict[str, dict[str, list[str]]],
    memo: dict[tuple[str, str], tuple[set[str], set[str], list[list[str]]]],
    trail: tuple[str, ...] = (),
) -> tuple[set[str], set[str], list[list[str]]]:
    key = (vdom, group_name)

    if key in memo:
        return memo[key]

    if group_name in trail:
        cycle_start = trail.index(group_name)
        cycle = list(trail[cycle_start:]) + [group_name]
        return set(), set(), [cycle]

    vdom_groups = groups.get(vdom, {})
    members = vdom_groups.get(group_name, [])

    effective: set[str] = set()
    nested: set[str] = set()
    cycles: list[list[str]] = []

    new_trail = trail + (group_name,)

    for member in set(members):
        if member in vdom_groups:
            nested.add(member)
            child_effective, child_nested, child_cycles = resolve_group(
                vdom,
                member,
                groups,
                memo,
                new_trail,
            )
            effective.update(child_effective)
            nested.update(child_nested)
            cycles.extend(child_cycles)
        else:
            effective.add(member)

    memo[key] = (effective, nested, cycles)
    return memo[key]


def build_recursive_indexes(data: ParsedData):
    memo: dict[
        tuple[str, str],
        tuple[set[str], set[str], list[list[str]]]
    ] = {}

    effective_members: dict[tuple[str, str], set[str]] = {}
    nested_groups: dict[tuple[str, str], set[str]] = {}
    cycles_by_group: dict[tuple[str, str], list[list[str]]] = {}

    for vdom, groups in data.groups.items():
        for group_name in groups:
            effective, nested, cycles = resolve_group(
                vdom,
                group_name,
                data.groups,
                memo,
            )
            effective_members[(vdom, group_name)] = effective
            nested_groups[(vdom, group_name)] = nested
            cycles_by_group[(vdom, group_name)] = cycles

    inherited_index: dict[tuple[str, str], list[str]] = defaultdict(list)

    for (vdom, group_name), members in effective_members.items():
        for member in members:
            inherited_index[(vdom, member)].append(group_name)

    for group_names in inherited_index.values():
        group_names.sort(key=str.lower)

    return effective_members, nested_groups, cycles_by_group, inherited_index


def format_full_report(data: ParsedData) -> str:
    vdoms = sorted(
        set(data.addresses) | set(data.groups),
        key=str.lower,
    )

    total_addresses = sum(len(items) for items in data.addresses.values())
    total_groups = sum(len(items) for items in data.groups.values())

    (
        effective_members,
        nested_groups,
        cycles_by_group,
        inherited_index,
    ) = build_recursive_indexes(data)

    direct_index = direct_membership_index(data)

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
    lines.append("=" * 110)
    lines.append("ADDRESS GROUP ANALYSIS")
    lines.append("=" * 110)

    if not data.groups:
        lines.append("")
        lines.append("No firewall.addrgrp configuration was found.")
    else:
        for vdom in sorted(data.groups, key=str.lower):
            groups = data.groups[vdom]

            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append("-" * 110)
            lines.append(
                f"{'Address group':<52}"
                f"{'Direct':>9}"
                f"{'Nested':>9}"
                f"{'Effective':>11}"
                f"{'Duplicates':>12}"
                f"{'Cycle':>9}"
            )

            for group_name in sorted(groups, key=str.lower):
                members = groups[group_name]
                counts = Counter(members)
                duplicate_entries = sum(
                    count - 1 for count in counts.values() if count > 1
                )
                cycle_flag = (
                    "Yes"
                    if cycles_by_group.get((vdom, group_name))
                    else "No"
                )

                lines.append(
                    f"{group_name:<52}"
                    f"{len(set(members)):>9,}"
                    f"{len(nested_groups.get((vdom, group_name), set())):>9,}"
                    f"{len(effective_members.get((vdom, group_name), set())):>11,}"
                    f"{duplicate_entries:>12,}"
                    f"{cycle_flag:>9}"
                )

    lines.append("")
    lines.append("=" * 110)
    lines.append("OBJECTS USED IN MULTIPLE GROUPS")
    lines.append("=" * 110)

    all_objects = set(direct_index) | set(inherited_index)
    reused = []

    for key in all_objects:
        direct_groups = direct_index.get(key, [])
        all_groups = inherited_index.get(key, [])

        if len(all_groups) > 1:
            reused.append((key[0], key[1], direct_groups, all_groups))

    if not reused:
        lines.append("")
        lines.append(
            "No object was found in multiple effective address groups "
            "within the same VDOM."
        )
    else:
        lines.append("")
        lines.append(f"Objects used in multiple effective groups: {len(reused):,}")

        for vdom, object_name, direct_groups, all_groups in sorted(
            reused,
            key=lambda item: (item[0].lower(), item[1].lower()),
        ):
            inherited_only = [
                group for group in all_groups if group not in direct_groups
            ]

            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append(f"Object: {object_name}")
            lines.append(f"Effective group count: {len(all_groups):,}")
            lines.append(
                "Direct groups: "
                + (", ".join(direct_groups) if direct_groups else "None")
            )
            lines.append(
                "Inherited parent groups: "
                + (", ".join(inherited_only) if inherited_only else "None")
            )

    lines.append("")
    lines.append("=" * 110)
    lines.append("NOTES")
    lines.append("=" * 110)
    lines.append(
        "• Use the filter to search for an address object or address group."
    )
    lines.append(
        "• Filter results include the object's complete configuration block."
    )
    lines.append(
        "• Address totals count explicit config firewall address entries only."
    )

    return "\n".join(lines)


def format_filter_results(data: ParsedData, query: str) -> str:
    query = query.strip()

    if not query:
        return "Enter an address object or address-group name, or part of a name."

    query_lower = query.lower()
    direct_index = direct_membership_index(data)
    (
        effective_members,
        nested_groups,
        cycles_by_group,
        inherited_index,
    ) = build_recursive_indexes(data)

    address_matches: set[tuple[str, str]] = set()
    group_matches: set[tuple[str, str]] = set()

    for vdom, objects in data.addresses.items():
        for object_name in objects:
            if query_lower in object_name.lower():
                address_matches.add((vdom, object_name))

    for (vdom, object_name) in set(direct_index) | set(inherited_index):
        if query_lower in object_name.lower():
            address_matches.add((vdom, object_name))

    for vdom, groups in data.groups.items():
        for group_name in groups:
            if query_lower in group_name.lower():
                group_matches.add((vdom, group_name))

    lines: list[str] = []
    lines.append(APP_NAME)
    lines.append(f'FILTER: "{query}"')
    lines.append("=" * 100)

    total_matches = len(address_matches) + len(group_matches)

    if total_matches == 0:
        lines.append("")
        lines.append("No matching address object or address group was found.")
        return "\n".join(lines)

    lines.append("")
    lines.append(
        f"Matches: {total_matches:,} "
        f"({len(address_matches):,} address object(s), "
        f"{len(group_matches):,} address group(s))"
    )

    if address_matches:
        lines.append("")
        lines.append("=" * 100)
        lines.append("ADDRESS OBJECT MATCHES")
        lines.append("=" * 100)

        for vdom, object_name in sorted(
            address_matches,
            key=lambda item: (item[0].lower(), item[1].lower()),
        ):
            direct_groups = direct_index.get((vdom, object_name), [])
            effective_groups = inherited_index.get((vdom, object_name), [])
            inherited_only = [
                group for group in effective_groups if group not in direct_groups
            ]
            explicitly_defined = object_name in data.addresses.get(vdom, set())

            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append(f"Object: {object_name}")
            lines.append(
                "Explicit firewall.address object: "
                + ("Yes" if explicitly_defined else "No / not found in file")
            )
            lines.append(f"Direct group membership count: {len(direct_groups):,}")
            lines.append(
                "Direct groups: "
                + (", ".join(direct_groups) if direct_groups else "None")
            )
            lines.append(
                f"Inherited parent-group count: {len(inherited_only):,}"
            )
            lines.append(
                "Inherited parent groups: "
                + (", ".join(inherited_only) if inherited_only else "None")
            )
            lines.append(
                f"Total effective group memberships: {len(effective_groups):,}"
            )
            lines.append("")
            lines.append("CONFIGURATION:")
            lines.append("-" * 100)
            lines.append(
                data.address_configs.get(
                    (vdom, object_name),
                    "Configuration block was not found in the selected file.",
                )
            )

    if group_matches:
        lines.append("")
        lines.append("=" * 100)
        lines.append("ADDRESS GROUP MATCHES")
        lines.append("=" * 100)

        for vdom, group_name in sorted(
            group_matches,
            key=lambda item: (item[0].lower(), item[1].lower()),
        ):
            members = data.groups[vdom][group_name]
            counts = Counter(members)
            duplicate_entries = sum(
                count - 1 for count in counts.values() if count > 1
            )

            parent_groups = direct_index.get((vdom, group_name), [])

            lines.append("")
            lines.append(f"VDOM: {vdom}")
            lines.append(f"Address group: {group_name}")
            lines.append(f"Direct unique members: {len(counts):,}")
            lines.append(
                f"Nested groups: "
                f"{len(nested_groups.get((vdom, group_name), set())):,}"
            )
            lines.append(
                f"Effective leaf addresses: "
                f"{len(effective_members.get((vdom, group_name), set())):,}"
            )
            lines.append(f"Duplicate direct entries: {duplicate_entries:,}")
            lines.append(
                "Circular reference: "
                + (
                    "Yes"
                    if cycles_by_group.get((vdom, group_name))
                    else "No"
                )
            )
            lines.append(
                "Direct parent groups: "
                + (", ".join(parent_groups) if parent_groups else "None")
            )
            lines.append("")
            lines.append("CONFIGURATION:")
            lines.append("-" * 100)
            lines.append(
                data.group_configs.get(
                    (vdom, group_name),
                    "Configuration block was not found in the selected file.",
                )
            )

    return "\n".join(lines)


class AnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1280x850")
        self.root.minsize(900, 600)

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
            text=(
                "Search address object or address group "
                "and show usage plus configuration"
            ),
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
            text="Search",
            command=self.apply_filter,
            padx=14,
        ).pack(side="left", padx=(8, 0))

        tk.Button(
            filter_frame,
            text="Clear Search",
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
