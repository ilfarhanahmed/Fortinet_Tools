# !/usr/bin/env python3
"""
FortiManager TAC Report Health Check Tool
by Farhan Ahmed - ETAC-AMER

Parses a FortiManager console_history / TAC report file and checks:
  - System identity (platform, version, serial, hostname)
  - VM license expiry  (diag debug vminfo)
  - CPU count and usage  (diag system print cpuinfo / get system performance)
  - RAM total and usage  (Memory info / get system performance)
  - Disk total and usage  (get system performance)
  - Sizing adequacy vs Fortinet minimum requirements
  - Device/VDOM count and list  (diag dvm device list)
  - Policy package install status per device
  - NTP status  (diag system ntp status)
  - HA mode  (get system ha)
  - Crash log presence  (diag debug crashlog read / event log)
  - Klog check (dia de klog)
  - Downgrade check (dia cdb upgrade summary)
  - ADOM list  (diag dvm adom list)
  - Task history  (task/task)
  - Flash disk usage

Sizing reference:
  https://docs.fortinet.com/document/fortimanager-private-cloud/7.6.0/
          kvm-administration-guide/583600/minimum-system-requirements
  Absolute minimum: 4 vCPU, 16 GB RAM (7.4.1+), 500 GB disk
  Per-scale requirements (max devices/VDOMs -> RAM GB, CPU cores):
    100   ->  16 GB,  4 cores
    300   ->  16 GB,  6 cores
    1200  ->  32 GB,  6 cores
    4000  ->  64 GB, 16 cores
    10000 -> 128 GB, 24 cores

"""

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Fortinet official sizing table (FMG 7.6, KVM guide)
# (max_devices_vdoms, min_ram_gb, min_cpu_cores)
# Absolute floor regardless of device count: 4 CPU, 16 GB RAM, 500 GB disk
# ---------------------------------------------------------------------------
SIZING_TABLE = [
    (100, 16, 4),
    (300, 16, 6),
    (1200, 32, 6),
    (4000, 64, 16),
    (10000, 128, 24),
]
ABS_MIN_CPU = 4
ABS_MIN_RAM_GB = 16
ABS_MIN_DISK_GB = 500
DISK_WARN_PCT = 75
DISK_CRIT_PCT = 90


# --------------
# Output helpers
# --------------

def section(title):
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def ok(msg):   print(f"  [OK  ] {msg}")


def warn(msg): print(f"  [WARN] {msg}")


def crit(msg): print(f"  [CRIT] {msg}")


def info(msg): print(f"  [INFO] {msg}")


# ------------
# File loader
# ------------

def load(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)


def section_text(text: str, start_marker: str, end_marker: str = "### ") -> str:
    """Return the text between start_marker and the next ### section."""
    idx = text.find(start_marker)
    if idx == -1:
        return ""
    start = idx + len(start_marker)
    end = text.find(end_marker, start)
    return text[start:end].strip() if end != -1 else text[start:].strip()


def first_match(pattern: str, text: str, flags=0):
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


# ------------------
# Individual checks
# ------------------

def check_system_status(text: str):
    section("System Status")
    block = section_text(text, "### get system status")

    fields = {
        "Platform Full Name": "Platform",
        "Version": "Version",
        "Serial Number": "Serial",
        "Hostname": "Hostname",
        "HA Mode": "HA Mode",
        "FIPS Mode": "FIPS Mode",
        "Disk Usage": "Disk Usage",
        "License Status": "License",
        "Image Signature": "Image Signature",
    }
    for key, label in fields.items():
        val = first_match(rf"^{re.escape(key)}\s*:\s*(.+)$", block, re.MULTILINE)
        if val is None:
            info(f"{label}: not found")
            continue
        if key == "License Status":
            (ok if val == "Valid" else crit)(f"{label}: {val}")
        elif key == "Image Signature":
            (ok if "GA Certified" in val else warn)(f"{label}: {val}")
        else:
            info(f"{label}: {val}")


def check_vm_license(text: str):
    section("VM License")
    block = section_text(text, "### diag debug vminfo")

    valid = "VM license is valid" in block
    expires = first_match(r"Expires in\s*:\s*(.+)", block)
    vm_type = first_match(r"^Type\s*:\s*(.+)$", block, re.MULTILINE)
    max_dev = first_match(r"^Max devices\s*:\s*(.+)$", block, re.MULTILINE)

    if valid:
        ok("License: valid")
    else:
        crit("License: NOT valid or status not found")

    if expires:
        # Warn if expiring soon (contains "days" and number <= 30)
        day_match = re.search(r"(\d+)\s*day", expires)
        days = int(day_match.group(1)) if day_match else 999
        (crit if days <= 7 else warn if days <= 30 else ok)(
            f"Expires in: {expires}"
        )
    else:
        warn("Expiry: not found")

    if vm_type: info(f"Type: {vm_type}")
    if max_dev: info(f"Max devices: {max_dev}")


def _parse_kb(s: str) -> float:
    """Parse strings like '8,161,460 KB' or '8161460' into float KB."""
    s = s.replace(",", "").replace(" KB", "").replace("KB", "").strip()
    try:
        return float(s)
    except ValueError:
        return 0.0


def check_performance(text: str):
    section("Resource Performance (get system performance)")
    # Use the second occurrence which is more complete
    idx1 = text.find("### get system performance")
    idx2 = text.find("### get system performance", idx1 + 1) if idx1 != -1 else -1
    start = idx2 if idx2 != -1 else idx1
    if start == -1:
        warn("get system performance section not found")
        return
    end = text.find("### ", start + 1)
    block = text[start:end].strip() if end != -1 else text[start:].strip()

    # CPU
    cpu_used = first_match(r"Used:\s+([\d.]+)%", block)
    if cpu_used:
        pct = float(cpu_used)
        (warn if pct > 80 else ok)(f"CPU used: {pct:.1f}%")
    else:
        warn("CPU usage: not found")

    # Memory (excluding swap)
    mem_total = first_match(r"Total \(Excluding Swap\):\s+([\d,]+\s*KB)", block)
    mem_used = first_match(r"Used \(Excluding Swap\):\s+([\d,]+\s*KB)\s+([\d.]+)%", block)
    mem_pct = first_match(r"Used \(Excluding Swap\):\s+[\d,]+\s*KB\s+([\d.]+)%", block)
    if mem_total and mem_pct:
        total_gb = _parse_kb(mem_total) / 1024 / 1024
        pct = float(mem_pct)
        (warn if pct > 85 else ok)(
            f"RAM used: {pct:.1f}%  (total: {total_gb:.1f} GB excl. swap)"
        )
    else:
        warn("Memory usage (excl. swap): not found")

    # Hard disk
    hd_total = first_match(r"Hard Disk:\s*\n\s*Total:\s+([\d,]+\s*KB)", block)
    hd_pct = first_match(r"Hard Disk:.*?Used:\s+[\d,]+\s*KB\s+([\d.]+)%", block, re.DOTALL)
    if hd_total and hd_pct:
        total_gb = _parse_kb(hd_total) / 1024 / 1024
        pct = float(hd_pct)
        fn = crit if pct > DISK_CRIT_PCT else (warn if pct > DISK_WARN_PCT else ok)
        fn(f"Disk used: {pct:.1f}%  (total: {total_gb:.1f} GB)")
    else:
        warn("Hard disk usage: not found")

    # Flash
    fl_pct = first_match(r"Flash Disk:.*?Used:\s+[\d,]+\s*KB\s+([\d.]+)%", block, re.DOTALL)
    if fl_pct:
        pct = float(fl_pct)
        (warn if pct > 80 else ok)(f"Flash used: {pct:.1f}%")


def check_sizing(text: str):
    section("Sizing Check (Fortinet Minimum Requirements, FMG 7.6)")
    info("Reference: docs.fortinet.com/document/fortimanager-private-cloud/"
         "7.6.0/kvm-administration-guide/583600/minimum-system-requirements")
    print()

    # ---------------------------
    # Collect actual resources
    # ---------------------------

    # vCPU: processor IDs are 0-based so count = max_id + 1
    cpu_block = section_text(text, "### diag system print cpuinfo")
    processors = re.findall(r"^processor\s*:\s*(\d+)", cpu_block, re.MULTILINE)
    vcpu_count = max(int(p) for p in processors) + 1 if processors else 0
    if vcpu_count == 0:
        hw_block = section_text(text, "### diag hardware info")
        processors = re.findall(r"^processor\s*:\s*(\d+)", hw_block, re.MULTILINE)
        vcpu_count = max(int(p) for p in processors) + 1 if processors else 0

    # RAM
    mem_block = section_text(text, "### Memory info")
    mem_total_kb_str = first_match(r"^MemTotal:\s+([\d]+)\s*kB", mem_block, re.MULTILINE)
    ram_gb = float(mem_total_kb_str) / 1024 / 1024 if mem_total_kb_str else 0.0

    # Disk
    perf_idx = text.find("### get system performance")
    perf_idx2 = text.find("### get system performance", perf_idx + 1)
    start = perf_idx2 if perf_idx2 != -1 else perf_idx
    perf_end = text.find("### ", start + 1) if start != -1 else -1
    perf_block = text[start:perf_end] if start != -1 and perf_end != -1 else ""
    hd_total_str = first_match(r"Hard Disk:\s*\n\s*Total:\s+([\d,]+)\s*KB", perf_block)
    disk_gb = _parse_kb(hd_total_str) / 1024 / 1024 if hd_total_str else 0.0

    # Managed device / VDOM count
    dvm_block = section_text(text, "### diag dvm device list")
    managed_m = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
    licensed_m = re.search(r"There are currently (\d+) devices/vdoms count for license", dvm_block)
    num_managed = int(managed_m.group(1)) if managed_m else 0
    num_licensed = int(licensed_m.group(1)) if licensed_m else 0

    # Print info
    info(f"Actual vCPU      : {vcpu_count if vcpu_count else 'not found'}"
         + (f"  (processors 0..{vcpu_count - 1})" if vcpu_count else ""))
    info(f"Actual RAM       : {ram_gb:.1f} GB")
    info(f"Actual Disk      : {disk_gb:.1f} GB")
    info(f"Devices managed  : {num_managed}  (licensed: {num_licensed})")
    print()

    # ------------------------------------------------------
    # Find the required tier for the current device count
    # -------------------------------------------------------
    current_tier = None
    next_tier = None
    for i, (max_dev, min_ram, min_cpu) in enumerate(SIZING_TABLE):
        if num_managed <= max_dev:
            current_tier = (max_dev, min_ram, min_cpu)
            if i + 1 < len(SIZING_TABLE):
                next_tier = SIZING_TABLE[i + 1]
            break
    if current_tier is None:
        current_tier = SIZING_TABLE[-1]

    req_max, req_ram, req_cpu = current_tier

    info(f"Required tier : up to {req_max} devices/VDOMs  ->  "
         f"{req_cpu} vCPU, {req_ram} GB RAM,  {ABS_MIN_DISK_GB} GB disk (min)")
    if next_tier:
        nx_max, nx_ram, nx_cpu = next_tier
        info(f"Next tier : up to {nx_max} devices/VDOMs  ->  "
             f"{nx_cpu} vCPU, {nx_ram} GB RAM,  {ABS_MIN_DISK_GB} GB disk (min)")
    print()

    # -------------------------------
    # Device count vs tier ceiling
    # --------------------------------
    pct_of_tier = (num_managed / req_max * 100) if req_max else 0
    info(f"Device count usage: {num_managed} / {req_max} ({pct_of_tier:.1f}% of current tier ceiling)")
    if pct_of_tier >= 80:
        warn(f"Device count is at {pct_of_tier:.0f}% of the {req_max}-device tier ceiling — "
             f"approaching limit, plan upgrade to next tier")
    elif pct_of_tier >= 60:
        warn(f"Device count is at {pct_of_tier:.0f}% of the {req_max}-device tier ceiling — "
             f"monitor growth")
    else:
        ok(f"Device count is at {pct_of_tier:.0f}% of the {req_max}-device tier ceiling — "
           f"capacity is adequate")
    print()

    # --------------
    # vCPU check--
    # --------------
    if vcpu_count == 0:
        warn("vCPU: could not determine from file")
    elif vcpu_count < ABS_MIN_CPU:
        crit(f"vCPU: {vcpu_count} is BELOW the absolute minimum of {ABS_MIN_CPU} "
             f"(required {req_cpu} for up to {req_max} devices)")
    elif vcpu_count < req_cpu:
        crit(f"vCPU: {vcpu_count} is BELOW the required {req_cpu} for {num_managed} devices "
             f"(tier: up to {req_max} devices requires {req_cpu} vCPU)")
    elif next_tier and vcpu_count < next_tier[2] and pct_of_tier >= 60:
        warn(f"vCPU: {vcpu_count} meets current tier ({req_cpu} required) but would be "
             f"insufficient for the next tier ({next_tier[2]} vCPU needed for up to {next_tier[0]} devices)")
    else:
        ok(f"vCPU: {vcpu_count} meets the requirement for this tier ({req_cpu} vCPU for up to {req_max} devices)")

    # ---------
    # RAM check
    # ---------
    if ram_gb == 0:
        warn("RAM: could not determine from file")
    elif ram_gb < ABS_MIN_RAM_GB:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW the absolute minimum of {ABS_MIN_RAM_GB} GB "
             f"(required {req_ram} GB for up to {req_max} devices)")
    elif ram_gb < req_ram:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW the required {req_ram} GB for {num_managed} devices "
             f"(tier: up to {req_max} devices requires {req_ram} GB)")
    elif ram_gb < req_ram * 1.1:
        warn(f"RAM: {ram_gb:.1f} GB meets minimum ({req_ram} GB) but headroom is tight")
    elif next_tier and ram_gb < next_tier[1] and pct_of_tier >= 60:
        warn(f"RAM: {ram_gb:.1f} GB meets current tier ({req_ram} GB required) but would be "
             f"insufficient for the next tier ({next_tier[1]} GB needed for up to {next_tier[0]} devices)")
    else:
        ok(f"RAM: {ram_gb:.1f} GB meets the requirement for this tier ({req_ram} GB for up to {req_max} devices)")

    # --------------
    # Disk check
    # --------------
    if disk_gb == 0:
        warn("Disk: could not determine from file")
    elif disk_gb < ABS_MIN_DISK_GB:
        crit(f"Disk: {disk_gb:.1f} GB is BELOW the absolute minimum of {ABS_MIN_DISK_GB} GB")
    elif disk_gb < ABS_MIN_DISK_GB * 1.1:
        warn(f"Disk: {disk_gb:.1f} GB meets the minimum ({ABS_MIN_DISK_GB} GB) but headroom is tight")
    else:
        ok(f"Disk: {disk_gb:.1f} GB meets the absolute minimum ({ABS_MIN_DISK_GB} GB)")


def check_devices(text: str):
    section("Managed Devices (diag dvm device list)")
    block = section_text(text, "### diag dvm device list")

    # Summary counts
    for pattern in [
        r"There are currently (\d+) devices/vdoms managed",
        r"There are currently (\d+) devices/vdoms count for license",
        r"There are currently (\d+) FortiAP managed",
        r"There are currently (\d+) FortiWiFi managed",
        r"There are currently (\d+) FortiSwitch managed",
        r"There are currently (\d+) FortiExtender managed",
    ]:
        m = re.search(pattern, block)
        if m:
            info(re.sub(r"(\d+)", m.group(1),
                        pattern.replace(r"(\d+)", m.group(1)).replace("\\", ""), 1))

    print()

    # Parse each device line
    # TYPE  OID  SN  HA  IP  NAME  ADOM  IPS  FIRMWARE  HW_GenX
    dev_pattern = re.compile(
        r"^(fmgfaz-managed|\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    lines = block.splitlines()
    i = 0
    found_any = False
    while i < len(lines):
        m = dev_pattern.match(lines[i])
        if m:
            found_any = True
            dtype, oid, sn, ha, ip, name, adom = m.groups()
            info(f"Device: {name}  SN={sn}  IP={ip}  ADOM={adom}")

            # STATUS line
            if i + 1 < len(lines) and "STATUS:" in lines[i + 1]:
                status_line = lines[i + 1].strip()
                conn_ok = "conn: up" in status_line
                conf_ok = "conf: in sync" in status_line
                (ok if conn_ok else crit)(
                    f"  Connection: {'up' if conn_ok else 'DOWN'}"
                )
                (ok if conf_ok else warn)(
                    f"  Config sync: {'in sync' if conf_ok else 'OUT OF SYNC'}"
                )

            # VDOM / policy package line(s)
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|-"):
                vdom_line = lines[j].strip()
                vdom_m = re.search(r"vdom:\[?\d+\]?(\w+).*?pkg:\[([^\]]+)\]", vdom_line)
                if vdom_m:
                    vname, pkg = vdom_m.groups()
                    if pkg == "never-installed":
                        crit(f"  vdom:{vname} policy package NEVER INSTALLED")
                    else:
                        ok(f"  vdom:{vname} policy pkg: {pkg}")
                j += 1
            print()
        i += 1

    if not found_any:
        warn("No device entries parsed from diag dvm device list")


def check_ntp(text: str):
    section("NTP Status (diag system ntp status)")
    block = section_text(text, "### diag system ntp status")
    if not block:
        warn("NTP status section not found")
        return

    lines = [l for l in block.splitlines() if l.strip()]
    for line in lines:
        info(line.strip())

    # Check for synchronised indicator
    if re.search(r"\*\s*\S+", block):  # leading * = selected peer
        ok("NTP peer selected and synchronised")
    elif "unsynchronised" in block.lower():
        crit("NTP: unsynchronised")
    else:
        warn("NTP: synchronisation status unclear — check output above")


# ----------
# HA config
# ----------

def check_ha(text: str):
    section("High Availability (get system ha)")
    block = section_text(text, "### get system ha")
    if not block:
        warn("HA section not found")
        return

    mode = first_match(r"^mode\s*:\s*(.+)$", block, re.MULTILINE)
    if mode is None:
        # Also check get system status
        status_block = section_text(text, "### get system status")
        mode = first_match(r"^HA Mode\s*:\s*(.+)$", status_block, re.MULTILINE)

    if mode:
        if mode.lower() in ("standalone", "0", "stand alone"):
            warn(f"HA mode: {mode} (no redundancy)")
        else:
            ok(f"HA mode: {mode}")
    else:
        warn("HA mode: not found")


# -----------
# Crash log
# ------------

def check_crash_log(text: str):
    section("Crash Log")
    # Look for crashlog section
    crash_markers = [
        "### diag debug crashlog read",
        "### diag debug crash read",
        "crashlog",
    ]
    block = ""
    for marker in crash_markers:
        block = section_text(text, marker)
        if block:
            break

    crash_kw = re.compile(
        r"(signal|segfault|bus error|aborted|coredump|killed|oom|"
        r"svc cdb|svc dvmdb|securityconsole.*crash|assert)", re.IGNORECASE
    )

    if not block:
        warn("No crashlog section found in file")
    else:
        crash_lines = [l for l in block.splitlines() if crash_kw.search(l)]
        if crash_lines:
            crit(f"Found {len(crash_lines)} crash-related line(s):")
            for line in crash_lines[:15]:
                crit(f"  {line.strip()}")
        else:
            ok("No crash keywords found in crashlog section")

    # Also scan the whole file for crash indicators outside dedicated section
    all_crash = re.findall(
        r"^.*(?:Signal \d+|Segmentation fault|Bus error|double free|"
        r"svc cdb reader.*crash|securityconsole.*abort).*$",
        text, re.IGNORECASE | re.MULTILINE
    )
    if all_crash:
        warn(f"Additional crash indicators found elsewhere in file ({len(all_crash)} line(s)):")
        for line in all_crash[:10]:
            warn(f"  {line.strip()[:120]}")


# ----------
# ADOM check
# ----------
def check_adoms(text: str):
    section("ADOM List (diag dvm adom list)")
    block = section_text(text, "### diag dvm adom list")
    if not block:
        warn("ADOM list section not found")
        return

    lines = [l for l in block.splitlines() if l.strip() and not l.startswith("-")]
    locked = [l for l in lines if "locked" in l.lower()]

    info(f"ADOM entries: {len(lines)}")
    if locked:
        warn(f"Locked ADOMs: {len(locked)}")
        for l in locked:
            warn(f"  {l.strip()}")
    else:
        ok("No locked ADOMs")

    for line in lines[:15]:
        print(f"    {line.strip()}")
    if len(lines) > 15:
        info(f"  ... and {len(lines) - 15} more")


# ----------
# License
# ----------
def check_license_list(text: str):
    section("License List (diag license list)")
    block = section_text(text, "### diag license list")
    if not block:
        warn("License list section not found")
        return

    lines = [l for l in block.splitlines() if l.strip()
             and not l.startswith("Name") and not l.startswith("-")]
    for line in lines:
        if "No License" in line:
            warn(line.strip())
        elif re.search(r"Valid|Licensed", line, re.IGNORECASE):
            ok(line.strip())
        else:
            info(line.strip())


# ----------
# Flash disk
# ----------
def check_flash(text: str):
    section("Flash Disk (diag system flash list)")
    block = section_text(text, "### diag system flash list")
    if not block:
        warn("Flash list section not found")
        return

    for line in block.splitlines():
        if re.search(r"\d+%", line):
            pct_m = re.search(r"(\d+)%", line)
            pct = int(pct_m.group(1)) if pct_m else 0
            (warn if pct > 80 else ok)(f"Flash: {line.strip()}")
        elif line.strip():
            info(line.strip())


# ----------
# tasks check
# ----------
def check_tasks(text: str):
    section("Task History (diag task task list)")
    # TAC reports sometimes include task output
    block = section_text(text, "### diag task task list")
    if not block:
        # Try alternate header
        block = section_text(text, "task/task")
    if not block:
        info("Task history section not found in this file")
        info("(Task history is available via GUI: Device Manager > Task Monitor)")
        return

    lines = [l for l in block.splitlines() if l.strip()]
    errors = [l for l in lines if re.search(r"error|fail|abort", l, re.IGNORECASE)]
    ok(f"Task lines found: {len(lines)}")
    if errors:
        warn(f"Tasks with error/fail: {len(errors)}")
        for l in errors:
            crit(f"  {l.strip()}")


# ----------
# Version
# ----------
def _parse_version(ver_str: str):
    """
    Parse a Fortinet version string like 'v7.4.10-build2778' into a tuple
    (major, minor, patch, build) for numeric comparison.
    """
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)-build(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups())
    # fallback: try v7.6.6
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups()) + (0,)
    return None


# ----------
# Upgrade
# ----------

def check_cdb_upgrade(text: str):
    """
    Parses 'diag cdb upgrade summary' to detect any downgrades in the
    FMG version chain.
    """
    section("CDB Upgrade History (diag cdb upgrade summary)")

    block = section_text(text, "### diag cdb upgrade summary")
    if not block:
        warn("diag cdb upgrade summary section not found in file")
        return

    # Version entries look like: "2026-04-14 16:54:50     v7.4.10-build2778 260126 (GA.M)"
    ver_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(v[\d.]+-build\d+[^\n]*?)$",
        re.MULTILINE,
    )
    entries = ver_pattern.findall(block)

    if not entries:
        warn("No version entries found in cdb upgrade summary")
        return

    info(f"CDB version chain ({len(entries)} entr{'y' if len(entries) == 1 else 'ies'}):")
    prev_ver = None
    prev_tuple = None
    downgrade_found = False

    for ts, ver_raw in entries:
        ver = ver_raw.strip()
        cur_tuple = _parse_version(ver)

        if prev_tuple is None:
            info(f"  {ts}  {ver}  (initial)")
        elif cur_tuple is not None and cur_tuple < prev_tuple:
            crit(f"  {ts}  {ver}  <-- DOWNGRADE from {prev_ver}")
            downgrade_found = True
        elif cur_tuple == prev_tuple:
            warn(f"  {ts}  {ver}  (same version re-initialised)")
        else:
            ok(f"  {ts}  {ver}  (upgrade from {prev_ver})")

        prev_ver = ver
        prev_tuple = cur_tuple

    print()
    if downgrade_found:
        crit("Downgrade(s) detected in CDB version chain — investigate before proceeding")
    else:
        ok("No downgrades detected in CDB version chain")


# --------------------------------------
# FDS sizing in case FMG is being used as FDS server
# ---------------------------------
def check_fds_sizing(text: str):
    """
    Checks FMG-as-FDS (FortiGuard Distribution Server) sizing based on:
      https://docs.fortinet.com/document/fortimanager/7.6.0/best-practices/14860/
              fortimanager-performance-and-sizing-in-closed-networks

    1. Detects whether FGD rating services are enabled (diag fmupdate view-service-info fgd)
    2. If FDS is active, calculates additional RAM required using Fortinet formula:
         VMtotal = FMGreq + 2 x (WFdb + IOTdb + FQdb + ASdb + AVQdb)
       Using Jan 2026 database sizes: WF=13 GB, IoT=18 GB, FQ=5 GB, AS=0.5 GB, AVQ=0.5 GB
    3. Checks fds-setting max-work against Fortinet's FDS worker recommendation table:
         1-50 devices   -> 1 worker  (default)
         50-1000        -> 10 workers
         1000-3000      -> 24 workers
         3000+          -> 24 workers
    """
    section("FDS Sizing (closed network / FortiGuard Distribution Server)")
    info("Reference: docs.fortinet.com/document/fortimanager/7.6.0/best-practices/14860/")

    # -----------------------------------------------
    # 1. Check which FGD rating services are enabled
    # ------------------------------------------------
    svc_block = section_text(text, "### diag fmupdate view-service-info fgd")
    if not svc_block:
        warn("diag fmupdate view-service-info fgd section not found")
        return

    svc_lines = [l.strip() for l in svc_block.splitlines() if ":" in l]
    enabled_svcs = [l for l in svc_lines if l.endswith(": on")]
    disabled_svcs = [l for l in svc_lines if l.endswith(": off")]

    info(f"FGD rating services enabled : {len(enabled_svcs)}")
    info(f"FGD rating services disabled: {len(disabled_svcs)}")
    print()

    if not enabled_svcs:
        ok("No FGD rating services are enabled — FMG is NOT acting as a local FortiGuard server")
        info("FDS RAM formula and worker checks are not applicable")
        info("If this FMG serves FortiGuard updates to managed devices in a closed network,")
        info("enable the required services and re-run this check")
        return

    # FDS is active — print which services are on
    for svc in enabled_svcs:
        ok(f"  Service active: {svc}")
    for svc in disabled_svcs:
        info(f"  Service off   : {svc}")
    print()

    # ---------------------------------------------------------------
    # 2. RAM formula
    # Primary: parse actual DB sizes from diag fmupdate fgd-dbver
    # Fallback: Jan 2026 estimates from Fortinet docs
    #   WF=13 GB, IoT=18 GB (3 dbs), FQ=5 GB, AS=0.5 GB, AVQ=0.5 GB
    # --------------------------------------------------------------

    # Jan 2026 fallback sizes (GB)
    FALLBACK_DB_SIZES = {
        "webfilter": 13.0,
        "iot": 18.0,
        "filequery": 5.0,
        "antispam": 0.5,
        "avquery": 0.5,
    }

    # Parse fgd-dbver: lines like "wf   Webfilter   00001.00123  2026-01-20  13.21G"
    # Size field may be in MB (e.g. 256.71M) or GB (e.g. 13.21G) or absent
    dbver_block = section_text(text, "### diag fmupdate fgd-dbver")

    def parse_dbver_size(size_str: str) -> float:
        """Convert '13.21G' or '256.71M' to GB float. Returns 0.0 if empty."""
        if not size_str:
            return 0.0
        size_str = size_str.strip()
        if size_str.endswith("G"):
            return float(size_str[:-1])
        if size_str.endswith("M"):
            return float(size_str[:-1]) / 1024
        if size_str.endswith("K"):
            return float(size_str[:-1]) / 1024 / 1024
        return 0.0

    # Map TAC report category codes to our DB keys
    # wf -> webfilter; iotm+iotr+iots -> iot; fq -> filequery
    # as1+as2+as4 -> antispam; av+av2 -> avquery
    DBVER_MAP = {
        "wf": "webfilter",
        "iotm": "iot", "iotr": "iot", "iots": "iot",
        "fq": "filequery",
        "as1": "antispam", "as2": "antispam", "as4": "antispam",
        "av": "avquery", "av2": "avquery",
    }

    # Parse each line: "code   Description   Version   DateTime   Size"
    actual_db_sizes = {}  # db_key -> GB (summed across sub-DBs)
    dbver_size_source = "Jan 2026 Fortinet doc estimates (DBs not yet downloaded)"

    if dbver_block:
        for line in dbver_block.splitlines():
            parts = line.split()
            # Need at least code + description; size is last column if present
            if len(parts) < 2:
                continue
            code = parts[0].lower()
            if code not in DBVER_MAP:
                continue
            # Size is the last token if it ends with G/M/K; otherwise absent
            size_gb = 0.0
            if parts[-1][-1] in ("G", "M", "K") and re.match(r"[\d.]+[GMK]$", parts[-1]):
                size_gb = parse_dbver_size(parts[-1])
            if size_gb > 0:
                db_key = DBVER_MAP[code]
                actual_db_sizes[db_key] = actual_db_sizes.get(db_key, 0.0) + size_gb

    if actual_db_sizes:
        dbver_size_source = "actual sizes from diag fmupdate fgd-dbver"

    # Map service on/off to DB keys
    SVC_MAP = {
        "webfilter": re.compile(r"webfilter.*: on", re.IGNORECASE),
        "iot": re.compile(r"iot.*: on", re.IGNORECASE),
        "filequery": re.compile(r"file query.*: on", re.IGNORECASE),
        "antispam": re.compile(r"antispam.*: on", re.IGNORECASE),
        "avquery": re.compile(r"antivirus query.*: on|outbreak.*: on", re.IGNORECASE),
    }

    # Get base FMGreq from actual RAM
    mem_block = section_text(text, "### Memory info")
    mem_total_kb_str = first_match(r"^MemTotal:\s+([\d]+)\s*kB", mem_block, re.MULTILINE)
    fmg_req_gb = float(mem_total_kb_str) / 1024 / 1024 if mem_total_kb_str else 0.0

    # Sum enabled DB sizes (prefer actual, fall back to estimates)
    enabled_db_total = 0.0
    active_dbs = []
    for db_key, pattern in SVC_MAP.items():
        if any(pattern.search(l) for l in svc_lines):
            if db_key in actual_db_sizes:
                size = actual_db_sizes[db_key]
                label = f"{db_key} ({size:.2f} GB — from fgd-dbver)"
            else:
                size = FALLBACK_DB_SIZES[db_key]
                label = f"{db_key} ({size:.1f} GB — Jan 2026 estimate)"
            enabled_db_total += size
            active_dbs.append(label)

    vm_total_required = fmg_req_gb + 2 * enabled_db_total

    info(f"DB sizes source       : {dbver_size_source}")
    info("FDS RAM requirement formula:")
    info(f"  VMtotal = FMGreq + 2 x (enabled DBs)")
    info(f"  FMGreq (actual RAM)   = {fmg_req_gb:.1f} GB")
    for db in active_dbs:
        info(f"  Enabled DB            : {db}")
    info(f"  Total DB size         = {enabled_db_total:.1f} GB")
    info(f"  VMtotal required      = {fmg_req_gb:.1f} + 2 x {enabled_db_total:.1f} = {vm_total_required:.1f} GB")
    print()

    if fmg_req_gb < vm_total_required:
        crit(f"RAM: {fmg_req_gb:.1f} GB actual is BELOW the FDS-adjusted requirement of {vm_total_required:.1f} GB")
        crit(f"  Additional RAM needed: {vm_total_required - fmg_req_gb:.1f} GB")
        crit("  Risk: high I/O wait, degraded FortiManager performance, possible OOM")
    else:
        ok(f"RAM: {fmg_req_gb:.1f} GB meets FDS-adjusted requirement of {vm_total_required:.1f} GB")

    print()

    # --------------------------------
    # 3. FDS worker (max-work) check
    # -------------------------------
    # FDS worker recommendation table (Fortinet docs):
    #   1-50 devices    -> 1  (default)
    #   50-1000         -> 10
    #   1000-3000       -> 24
    #   3000+           -> 24
    FDS_WORKER_TABLE = [
        (50, 1, "1-50 devices"),
        (1000, 10, "50-1000 devices"),
        (3000, 24, "1000-3000 devices"),
        (9999999, 24, "3000+ devices"),
    ]

    # Get device count
    dvm_block = section_text(text, "### diag dvm device list")
    managed_m = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
    num_devices = int(managed_m.group(1)) if managed_m else 0

    # Get configured max-work from fds-setting block
    fds_block = section_text(text, "config fmupdate fds-setting")
    maxwork_m = re.search(r"set\s+max-work\s+(\d+)", fds_block)
    max_work = int(maxwork_m.group(1)) if maxwork_m else 1  # default is 1

    # Find recommended workers
    recommended_workers = 1
    recommended_label = "1-50 devices"
    for threshold, workers, label in FDS_WORKER_TABLE:
        if num_devices <= threshold:
            recommended_workers = workers
            recommended_label = label
            break

    info(f"Managed devices       : {num_devices}")
    info(f"Configured max-work   : {max_work}{' (default)' if not maxwork_m else ''}")
    info(f"Recommended max-work  : {recommended_workers}  (for {recommended_label})")
    print()

    if max_work < recommended_workers:
        crit(f"FDS workers: {max_work} is BELOW recommended {recommended_workers} for {num_devices} devices")
        crit(f"  Impact: AV/IPS updates will be slow and CPU usage will be high")
        crit(f"  Fix: config fmupdate fds-setting -> set max-work {recommended_workers}")
    elif max_work == recommended_workers:
        ok(f"FDS workers: {max_work} matches recommendation for {num_devices} devices")
    else:
        ok(f"FDS workers: {max_work} exceeds minimum recommendation ({recommended_workers}) for {num_devices} devices")
        if max_work > 24:
            warn("Note: Fortinet docs state there is no benefit to max-work above 24")


# ----------
# Klog
# ----------
def check_klog(text: str):
    section("Kernel Log (diag debug klog)")

    block = section_text(text, "### diag debug klog")
    if not block:
        warn("diag debug klog section not found in file")
        return

    # Parse the block line-by-line, tracking the current @@@ boot timestamp
    # and annotating each matching line with a resolved wall-clock time.
    boot_ts_pattern = re.compile(r"^@@@(.+)$")
    uptime_pattern = re.compile(r"^\s*<?[^>]*>?\s*\[\s*([\d.]+)\]")
    oom_pattern = re.compile(
        r"out.of.memory|oom.killer|oom-kill(?:er)?|killed process"
        r"|oom_score|cannot allocate memory",
        re.IGNORECASE,
    )
    fsck_pattern = re.compile(
        r"e2fsck|fsck|maximal mount count reached"
        r"|ext[234]-fs.{0,10}error|ext[234]-fs.{0,10}warning"
        r"|journal.*abort|i/o error.*block|bad block"
        r"|filesystem.*corrupt|remount.*read.only",
        re.IGNORECASE,
    )

    def resolve_time(boot_str: str, uptime_secs: float) -> str:
        """Add uptime_secs to the @@@ boot timestamp and return a string."""
        # @@@ format: "Mon Mar 16 12:48:35 2026"
        for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"):
            try:
                from datetime import datetime, timedelta
                dt = datetime.strptime(boot_str.strip(), fmt)
                dt += timedelta(seconds=uptime_secs)
                return dt.strftime("%a %b %d %H:%M:%S %Y")
            except ValueError:
                continue
        return boot_str.strip()

    current_boot = None
    oom_hits = []  # list of (wall_clock_str, raw_line)
    fsck_hits = []

    for line in block.splitlines():
        m = boot_ts_pattern.match(line)
        if m:
            current_boot = m.group(1)
            continue

        is_oom = bool(oom_pattern.search(line))
        is_fsck = bool(fsck_pattern.search(line))
        if not (is_oom or is_fsck):
            continue

        # Resolve wall-clock time
        wall = current_boot or "unknown boot time"
        um = uptime_pattern.match(line)
        if um and current_boot:
            try:
                wall = resolve_time(current_boot, float(um.group(1)))
            except Exception:
                pass

        if is_oom:
            oom_hits.append((wall, line.strip()))
        if is_fsck:
            fsck_hits.append((wall, line.strip()))

    # OOM results
    if oom_hits:
        crit(f"Out-of-memory events found: {len(oom_hits)}")
        for wall, line in oom_hits[:10]:
            crit(f"  [{wall}]  {line[:100]}")
        if len(oom_hits) > 10:
            crit(f"  ... and {len(oom_hits) - 10} more")
    else:
        ok("No out-of-memory events found in kernel log")

    # fsck / filesystem results
    if fsck_hits:
        errors = [(w, l) for w, l in fsck_hits
                  if re.search(r"error|abort|corrupt|read.only|bad block|i/o error", l, re.IGNORECASE)]
        warnings = [(w, l) for w, l in fsck_hits if (w, l) not in errors]

        if errors:
            crit(f"Filesystem errors found: {len(errors)}")
            for wall, line in errors[:10]:
                crit(f"  [{wall}]  {line[:100]}")
        if warnings:
            warn(f"Filesystem warnings found: {len(warnings)}")
            for wall, line in warnings[:10]:
                warn(f"  [{wall}]  {line[:100]}")
            if len(warnings) > 10:
                warn(f"  ... and {len(warnings) - 10} more")
    else:
        ok("No fsck or filesystem errors/warnings found in kernel log")


# ----------
# FIPS/ADOM config
# ----------

def check_security_config(text: str):
    """
    Checks FIPS mode and Admin Domain (ADOM) configuration status
    from 'get system status'.

    FIPS mode: should be Enabled in high-security/compliance environments.
    ADOM config: Enabled means multi-tenancy is active; Disabled means
                 all devices share a single management domain (root).
    """
    section("Security Config (FIPS Mode / Admin Domain)")

    block = section_text(text, "### get system status")

    # FIPS Mode
    fips = first_match(r"^FIPS Mode\s*:\s*(.+)$", block, re.MULTILINE)
    if fips is None:
        warn("FIPS Mode: not found in get system status")
    elif fips.strip().lower() == "enabled":
        ok(f"FIPS Mode: {fips.strip()} — cryptographic compliance enforced")
    else:
        warn(f"FIPS Mode: {fips.strip()} — not enabled; required for FIPS-compliant deployments")

    # Admin Domain (ADOM) Configuration
    adom_cfg = first_match(r"^Admin Domain Configuration\s*:\s*(.+)$", block, re.MULTILINE)
    max_adoms = first_match(r"^Max Number of Admin Domains\s*:\s*(.+)$", block, re.MULTILINE)

    if adom_cfg is None:
        warn("Admin Domain Configuration: not found in get system status")
    elif adom_cfg.strip().lower() == "enabled":
        ok(f"Admin Domain Configuration: {adom_cfg.strip()} (multi-tenancy active)")
        if max_adoms:
            info(f"Max Admin Domains: {max_adoms.strip()}")
    else:
        warn(f"Admin Domain Configuration: {adom_cfg.strip()} — all devices share the root ADOM")
        info("Consider enabling ADOMs if managing devices across multiple organisations or segments")
        if max_adoms:
            info(f"Max Admin Domains (if enabled): {max_adoms.strip()}")


CHECKS = [
    ("System Status", check_system_status),
    ("Security Config", check_security_config),
    ("VM License", check_vm_license),
    ("Performance", check_performance),
    ("Sizing Adequacy", check_sizing),
    ("Managed Devices", check_devices),
    ("NTP", check_ntp),
    ("High Availability", check_ha),
    ("Crash Log", check_crash_log),
    ("ADOM List", check_adoms),
    ("License List", check_license_list),
    ("Flash Disk", check_flash),
    ("Task History", check_tasks),
    ("CDB Upgrade History", check_cdb_upgrade),
    ("FDS Sizing", check_fds_sizing),
    ("Kernel Log", check_klog),
]


# ----------
# MAIN
# ----------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <tac_report_file>")
        sys.exit(1)

    path = sys.argv[1]
    print()
    print("FortiManager TAC Report Health Check")
    print("-" * 40)
    print(f"  File: {path}")

    text = load(path)
    print(f"  Size: {len(text):,} chars  /  {text.count(chr(10)):,} lines")

    # Track crit/warn counts by intercepting print output per section
    import io, contextlib

    results = {}  # label -> (crits, warns, exception_msg)
    for label, fn in CHECKS:
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                fn(text)
            output = buf.getvalue()
            print(output, end="")
            crits = output.count("[CRIT]")
            warns = output.count("[WARN]")
            results[label] = (crits, warns, None)
        except KeyboardInterrupt:
            print("\n  Interrupted")
            break
        except Exception as e:
            print(buf.getvalue(), end="")
            results[label] = (0, 0, str(e))
            print(f"\n  [EXCEPTION in {label}] {e}")

    section("Summary")
    for label, _ in CHECKS:
        if label not in results:
            warn(f"{label} - skipped")
            continue
        n_crit, n_warn, exc = results[label]
        if exc:
            crit(f"{label} - exception: {exc}")
        elif n_crit:
            crit(f"{label} - {n_crit} critical finding(s)")
        elif n_warn:
            warn(f"{label} - {n_warn} warning(s)")
        else:
            ok(label)
    print()


if __name__ == "__main__":
    main()