#!/usr/bin/env python3
"""
FortiGate Address and Address Group Analyzer v6
by Farhan Ahmed | www.farhan.ch

Improved UI:
- Styled headings
- Bold section titles
- Color-coded warnings and results
- Monospaced tabular output
- Search results with highlighted object/group names
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


APP_NAME = "FortiGate Address Group Analyzer v6"

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
            text="Search address object or address group",
            padx=10,
            pady=8,
        )
        filter_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.filter_value = tk.StringVar()

        filter_entry = tk.Entry(
            filter_frame,
            textvariable=self.filter_value,
            font=("Segoe UI", 10),
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
            padx=12,
            pady=12,
            bg="#ffffff",
            fg="#202124",
            insertbackground="#202124",
        )
        self.output.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10),
        )

        self.configure_tags()
        self.show_welcome()

    def configure_tags(self) -> None:
        self.output.tag_configure(
            "title",
            font=("Segoe UI", 16, "bold"),
            foreground="#1f4e79",
            spacing1=4,
            spacing3=8,
        )
        self.output.tag_configure(
            "subtitle",
            font=("Segoe UI", 10, "italic"),
            foreground="#5f6368",
            spacing3=8,
        )
        self.output.tag_configure(
            "section",
            font=("Segoe UI", 12, "bold"),
            foreground="#ffffff",
            background="#1f4e79",
            spacing1=12,
            spacing3=6,
            lmargin1=4,
            lmargin2=4,
        )
        self.output.tag_configure(
            "vdom",
            font=("Segoe UI", 10, "bold"),
            foreground="#0b5394",
            spacing1=6,
        )
        self.output.tag_configure(
            "header",
            font=("Consolas", 10, "bold"),
            foreground="#202124",
            background="#e8eef7",
        )
        self.output.tag_configure(
            "total",
            font=("Consolas", 10, "bold"),
            foreground="#1b5e20",
            background="#e8f5e9",
        )
        self.output.tag_configure(
            "warning",
            font=("Segoe UI", 10, "bold"),
            foreground="#b71c1c",
            background="#ffebee",
        )
        self.output.tag_configure(
            "success",
            font=("Segoe UI", 10, "bold"),
            foreground="#1b5e20",
        )
        self.output.tag_configure(
            "object",
            font=("Segoe UI", 10, "bold"),
            foreground="#6a1b9a",
        )
        self.output.tag_configure(
            "group",
            font=("Segoe UI", 10, "bold"),
            foreground="#e65100",
        )
        self.output.tag_configure(
            "label",
            font=("Segoe UI", 10, "bold"),
            foreground="#37474f",
        )
        self.output.tag_configure(
            "config",
            font=("Consolas", 10),
            foreground="#1f2937",
            background="#f6f8fa",
            lmargin1=12,
            lmargin2=12,
            spacing1=4,
            spacing3=8,
        )
        self.output.tag_configure(
            "note",
            font=("Segoe UI", 9, "italic"),
            foreground="#5f6368",
        )

    def clear_output(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")

    def lock_output(self) -> None:
        self.output.configure(state="disabled")

    def insert(self, text: str, tag: str | None = None) -> None:
        if tag:
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", text)

    def show_welcome(self) -> None:
        self.clear_output()
        self.insert(APP_NAME + "\n", "title")
        self.insert(
            "Load a FortiGate configuration, log, TAC report, "
            ".gz, .tar.gz, or .tgz file.\n",
            "subtitle",
        )
        self.lock_output()

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
            messagebox.showerror("Unable to analyze file", str(exc))

    def show_full_report(self) -> None:
        if self.data is None:
            self.show_welcome()
            return

        data = self.data
        (
            effective_members,
            nested_groups,
            cycles_by_group,
            inherited_index,
        ) = build_recursive_indexes(data)

        direct_index = direct_membership_index(data)

        self.clear_output()

        self.insert(APP_NAME + "\n", "title")
        self.insert(f"File: {data.selected_file}\n", "subtitle")

        self.insert("SUMMARY BY VDOM\n", "section")
        self.insert(
            f"{'VDOM':<38}{'Addresses':>12}{'Address groups':>16}\n",
            "header",
        )

        vdoms = sorted(
            set(data.addresses) | set(data.groups),
            key=str.lower,
        )

        total_addresses = 0
        total_groups = 0

        for vdom in vdoms:
            address_count = len(data.addresses.get(vdom, set()))
            group_count = len(data.groups.get(vdom, {}))
            total_addresses += address_count
            total_groups += group_count

            self.insert(
                f"{vdom:<38}{address_count:>12,}{group_count:>16,}\n"
            )

        self.insert(
            f"{'TOTAL':<38}{total_addresses:>12,}{total_groups:>16,}\n",
            "total",
        )

        self.insert("\nADDRESS GROUP ANALYSIS\n", "section")

        for vdom in sorted(data.groups, key=str.lower):
            self.insert(f"\nVDOM: {vdom}\n", "vdom")
            self.insert(
                f"{'Address group':<52}"
                f"{'Direct':>9}"
                f"{'Nested':>9}"
                f"{'Effective':>11}"
                f"{'Duplicates':>12}"
                f"{'Cycle':>9}\n",
                "header",
            )

            for group_name in sorted(data.groups[vdom], key=str.lower):
                members = data.groups[vdom][group_name]
                counts = Counter(members)
                duplicate_entries = sum(
                    count - 1 for count in counts.values() if count > 1
                )
                cycle_flag = (
                    "Yes"
                    if cycles_by_group.get((vdom, group_name))
                    else "No"
                )

                tag = "warning" if duplicate_entries or cycle_flag == "Yes" else None

                self.insert(
                    f"{group_name:<52}"
                    f"{len(set(members)):>9,}"
                    f"{len(nested_groups.get((vdom, group_name), set())):>9,}"
                    f"{len(effective_members.get((vdom, group_name), set())):>11,}"
                    f"{duplicate_entries:>12,}"
                    f"{cycle_flag:>9}\n",
                    tag,
                )

        self.insert("\nOBJECTS USED IN MULTIPLE GROUPS\n", "section")

        reused = []
        all_objects = set(direct_index) | set(inherited_index)

        for key in all_objects:
            direct_groups = direct_index.get(key, [])
            all_groups = inherited_index.get(key, [])
            if len(all_groups) > 1:
                reused.append((key[0], key[1], direct_groups, all_groups))

        if not reused:
            self.insert(
                "No object was found in multiple effective address groups "
                "within the same VDOM.\n",
                "success",
            )
        else:
            self.insert(
                f"Objects used in multiple effective groups: {len(reused):,}\n",
                "warning",
            )

            for vdom, object_name, direct_groups, all_groups in sorted(
                reused,
                key=lambda item: (item[0].lower(), item[1].lower()),
            ):
                inherited_only = [
                    group for group in all_groups if group not in direct_groups
                ]

                self.insert("\nVDOM: ", "label")
                self.insert(vdom + "\n", "vdom")
                self.insert("Object: ", "label")
                self.insert(object_name + "\n", "object")
                self.insert(
                    f"Effective group count: {len(all_groups):,}\n"
                )
                self.insert(
                    "Direct groups: "
                    + (", ".join(direct_groups) if direct_groups else "None")
                    + "\n"
                )
                self.insert(
                    "Inherited parent groups: "
                    + (", ".join(inherited_only) if inherited_only else "None")
                    + "\n"
                )

        self.insert("\nNOTES\n", "section")
        self.insert(
            "Direct = explicitly configured members. "
            "Nested = recursively referenced groups. "
            "Effective = unique leaf address objects after expansion.\n",
            "note",
        )

        self.lock_output()

    def apply_filter(self) -> None:
        if self.data is None:
            messagebox.showinfo(
                "No file loaded",
                "Load a FortiGate file first.",
            )
            return

        query = self.filter_value.get().strip()

        if not query:
            messagebox.showinfo(
                "Search",
                "Enter an address object or address-group name.",
            )
            return

        data = self.data
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

        self.clear_output()
        self.insert(APP_NAME + "\n", "title")
        self.insert(f'Search results for: "{query}"\n', "subtitle")

        total_matches = len(address_matches) + len(group_matches)

        if total_matches == 0:
            self.insert(
                "No matching address object or address group was found.\n",
                "warning",
            )
            self.lock_output()
            return

        self.insert(
            f"Matches: {total_matches:,} "
            f"({len(address_matches):,} address object(s), "
            f"{len(group_matches):,} address group(s))\n",
            "success",
        )

        if address_matches:
            self.insert("\nADDRESS OBJECT MATCHES\n", "section")

            for vdom, object_name in sorted(
                address_matches,
                key=lambda item: (item[0].lower(), item[1].lower()),
            ):
                direct_groups = direct_index.get((vdom, object_name), [])
                effective_groups = inherited_index.get((vdom, object_name), [])
                inherited_only = [
                    group for group in effective_groups if group not in direct_groups
                ]
                explicitly_defined = (
                    object_name in data.addresses.get(vdom, set())
                )

                self.insert("\nVDOM: ", "label")
                self.insert(vdom + "\n", "vdom")
                self.insert("Object: ", "label")
                self.insert(object_name + "\n", "object")
                self.insert(
                    "Explicit firewall.address object: "
                    + ("Yes" if explicitly_defined else "No / not found in file")
                    + "\n",
                    "success" if explicitly_defined else "warning",
                )
                self.insert(
                    f"Direct group membership count: {len(direct_groups):,}\n"
                )
                self.insert(
                    "Direct groups: "
                    + (", ".join(direct_groups) if direct_groups else "None")
                    + "\n"
                )
                self.insert(
                    f"Inherited parent-group count: {len(inherited_only):,}\n"
                )
                self.insert(
                    "Inherited parent groups: "
                    + (", ".join(inherited_only) if inherited_only else "None")
                    + "\n"
                )
                self.insert(
                    f"Total effective group memberships: "
                    f"{len(effective_groups):,}\n"
                )
                self.insert("\nCONFIGURATION\n", "header")
                self.insert(
                    data.address_configs.get(
                        (vdom, object_name),
                        "Configuration block was not found in the selected file.",
                    )
                    + "\n",
                    "config",
                )

        if group_matches:
            self.insert("\nADDRESS GROUP MATCHES\n", "section")

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

                self.insert("\nVDOM: ", "label")
                self.insert(vdom + "\n", "vdom")
                self.insert("Address group: ", "label")
                self.insert(group_name + "\n", "group")
                self.insert(f"Direct unique members: {len(counts):,}\n")
                self.insert(
                    f"Nested groups: "
                    f"{len(nested_groups.get((vdom, group_name), set())):,}\n"
                )
                self.insert(
                    f"Effective leaf addresses: "
                    f"{len(effective_members.get((vdom, group_name), set())):,}\n"
                )

                duplicate_tag = "warning" if duplicate_entries else "success"
                self.insert(
                    f"Duplicate direct entries: {duplicate_entries:,}\n",
                    duplicate_tag,
                )

                has_cycle = bool(cycles_by_group.get((vdom, group_name)))
                self.insert(
                    "Circular reference: "
                    + ("Yes" if has_cycle else "No")
                    + "\n",
                    "warning" if has_cycle else "success",
                )
                self.insert(
                    "Direct parent groups: "
                    + (", ".join(parent_groups) if parent_groups else "None")
                    + "\n"
                )
                self.insert("\nCONFIGURATION\n", "header")
                self.insert(
                    data.group_configs.get(
                        (vdom, group_name),
                        "Configuration block was not found in the selected file.",
                    )
                    + "\n",
                    "config",
                )

        self.lock_output()

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
