# !/usr/bin/env python3
"""
FortiManager / FortiAnalyzer TAC Report Health Check Tool
by Farhan Ahmed - ETAC-AMER

Checks:
  - System Status
  - VM License
  - Resource Performance
  - Sizing Adequacy
  - CDB Upgrade History
  - FDS Sizing (FMG only)
  - FAZ Log Rate and Sizing (FAZ only)
  - Kernel Log (OOM / fsck)
"""

import re
import sys
from pathlib import Path
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Fortinet sizing tables
# ---------------------------------------------------------------------------

# FMG VM sizing (KVM guide 7.6)
# (max_devices_vdoms, min_ram_gb, min_cpu_cores)
FMG_SIZING_TABLE = [
    (100,   16,  4),
    (300,   16,  6),
    (1200,  32,  6),
    (4000,  64, 16),
    (10000, 128, 24),
]
FMG_ABS_MIN_CPU     = 4
FMG_ABS_MIN_RAM_GB  = 16
FMG_ABS_MIN_DISK_GB = 500

# FAZ VM sizing (KVM guide 8.0)
# (analytic_rate, min_ram_gb, min_cpu, min_iops)
FAZ_SIZING_TABLE = [
    ( 3000, 16,  4,   300),
    ( 4000, 16,  4,   400),
    ( 5000, 16,  4,   500),
    ( 6000, 16,  8,   600),
    ( 7000, 16,  8,   700),
    ( 8000, 16,  8,   800),
    ( 9000, 16,  8,   900),
    (10000, 16,  8,  1000),
    (20000, 32, 16,  2000),
    (30000, 32, 16,  3000),
    (40000, 64, 32,  4000),
    (50000, 64, 32,  5000),
]

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
    idx = text.find(start_marker)
    if idx == -1:
        return ""
    start = idx + len(start_marker)
    end   = text.find(end_marker, start)
    return text[start:end].strip() if end != -1 else text[start:].strip()


def first_match(pattern: str, text: str, flags=0):
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None


def _parse_kb(s: str) -> float:
    s = str(s).replace(",", "").replace(" KB", "").replace("KB", "").strip()
    try:
        return float(s)
    except ValueError:
        return 0.0


def _parse_version(ver_str: str):
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)-build(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups())
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups()) + (0,)
    return None


# ------------------
# Individual checks
# ------------------

def check_system_status(text: str):
    section("System Status")
    block = section_text(text, "### get system status")

    fields = {
        "Platform Full Name":           "Platform",
        "Version":                      "Version",
        "Serial Number":                "Serial",
        "Hostname":                     "Hostname",
        "HA Mode":                      "HA Mode",
        "Disk Usage":                   "Disk Usage",
        "License Status":               "License",
        "Image Signature":              "Image Signature",
        "Admin Domain Configuration":   "ADOM Config",
        "Max Number of Admin Domains":  "Max ADOMs",
        "FIPS Mode":                    "FIPS Mode",
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
        elif key == "FIPS Mode":
            (ok if val.lower() == "enabled" else warn)(f"{label}: {val}")
        elif key == "Admin Domain Configuration":
            (ok if val.lower() == "enabled" else warn)(f"{label}: {val}")
        else:
            info(f"{label}: {val}")


def check_vm_license(text: str):
    section("VM License")

    status_block  = section_text(text, "### get system status")
    platform_type = first_match(r"^Platform Type\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    if "-VM" not in platform_type.upper():
        info("Hardware appliance — VM license check not applicable")
        info("License status is shown under System Status")
        return

    block   = section_text(text, "### diag debug vminfo")
    valid   = "VM license is valid" in block
    expires = first_match(r"Expires in\s*:\s*(.+)", block)
    vm_type = first_match(r"^Type\s*:\s*(.+)$", block, re.MULTILINE)
    max_dev = first_match(r"^Max devices\s*:\s*(.+)$", block, re.MULTILINE)

    (ok if valid else crit)("License: valid" if valid else "License: NOT valid or status not found")

    if expires:
        day_match = re.search(r"(\d+)\s*day", expires)
        days = int(day_match.group(1)) if day_match else 999
        (crit if days <= 7 else warn if days <= 30 else ok)(f"Expires in: {expires}")
    else:
        warn("Expiry: not found")

    if vm_type: info(f"Type: {vm_type}")
    if max_dev: info(f"Max devices: {max_dev}")


def check_performance(text: str):
    section("Resource Performance (get system performance)")
    idx1  = text.find("### get system performance")
    idx2  = text.find("### get system performance", idx1 + 1) if idx1 != -1 else -1
    start = idx2 if idx2 != -1 else idx1
    if start == -1:
        warn("get system performance section not found")
        return
    end   = text.find("### ", start + 1)
    block = text[start:end].strip() if end != -1 else text[start:].strip()

    cpu_used = first_match(r"Used:\s+([\d.]+)%", block)
    if cpu_used:
        pct = float(cpu_used)
        (warn if pct > 80 else ok)(f"CPU used: {pct:.1f}%")
    else:
        warn("CPU usage: not found")

    mem_total = first_match(r"Total \(Excluding Swap\):\s+([\d,]+\s*KB)", block)
    mem_pct   = first_match(r"Used \(Excluding Swap\):\s+[\d,]+\s*KB\s+([\d.]+)%", block)
    if mem_total and mem_pct:
        pct      = float(mem_pct)
        total_gb = _parse_kb(mem_total) / 1024 / 1024
        (warn if pct > 85 else ok)(f"RAM used: {pct:.1f}%  (total: {total_gb:.1f} GB excl. swap)")
    else:
        warn("Memory usage (excl. swap): not found")

    hd_total = first_match(r"Hard Disk:\s*\n\s*Total:\s+([\d,]+\s*KB)", block)
    hd_pct   = first_match(r"Hard Disk:.*?Used:\s+[\d,]+\s*KB\s+([\d.]+)%", block, re.DOTALL)
    if hd_total and hd_pct:
        pct      = float(hd_pct)
        total_gb = _parse_kb(hd_total) / 1024 / 1024
        fn = crit if pct > DISK_CRIT_PCT else (warn if pct > DISK_WARN_PCT else ok)
        fn(f"Disk used: {pct:.1f}%  (total: {total_gb:.1f} GB)")
    else:
        warn("Hard disk usage: not found")

    fl_pct = first_match(r"Flash Disk:.*?Used:\s+[\d,]+\s*KB\s+([\d.]+)%", block, re.DOTALL)
    if fl_pct:
        pct = float(fl_pct)
        (warn if pct > 80 else ok)(f"Flash used: {pct:.1f}%")


def check_sizing(text: str):
    section("Sizing Check (Fortinet Minimum Requirements)")

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    platform_type = first_match(r"^Platform Type\s*:\s*(.+)$",      status_block, re.MULTILINE) or ""
    is_vm         = "-VM" in platform_type.upper()
    is_faz        = "FortiAnalyzer" in platform_full

    if not is_vm:
        info(f"Platform: {platform_type}")
        info("Physical hardware appliance — VM resource checks do not apply")
        info("Refer to the hardware datasheet for this model's specifications")
        dvm_block  = section_text(text, "### diag dvm device list")
        managed_m  = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
        licensed_m = re.search(r"There are currently (\d+) devices/vdoms count for license", dvm_block)
        info(f"Devices managed: {managed_m.group(1) if managed_m else 'N/A'}  "
             f"(licensed: {licensed_m.group(1) if licensed_m else 'N/A'})")
        return

    if is_faz:
        info("FortiAnalyzer VM sizing is evaluated under FAZ Log Rate check")
        return

    # FMG VM sizing
    info("Reference: docs.fortinet.com/document/fortimanager-private-cloud/"
         "7.6.0/kvm-administration-guide/583600/minimum-system-requirements")
    print()

    cpu_block  = section_text(text, "### diag system print cpuinfo")
    processors = re.findall(r"^processor\s*:\s*(\d+)", cpu_block, re.MULTILINE)
    if not processors:
        hw_block   = section_text(text, "### diag hardware info")
        processors = re.findall(r"^processor\s*:\s*(\d+)", hw_block, re.MULTILINE)
    vcpu_count = max(int(p) for p in processors) + 1 if processors else 0

    mem_block        = section_text(text, "### Memory info")
    mem_total_kb_str = first_match(r"^MemTotal:\s+([\d]+)\s*kB", mem_block, re.MULTILINE)
    ram_gb           = float(mem_total_kb_str) / 1024 / 1024 if mem_total_kb_str else 0.0

    perf_idx  = text.find("### get system performance")
    perf_idx2 = text.find("### get system performance", perf_idx + 1)
    start     = perf_idx2 if perf_idx2 != -1 else perf_idx
    perf_end  = text.find("### ", start + 1) if start != -1 else -1
    perf_block   = text[start:perf_end] if start != -1 and perf_end != -1 else ""
    hd_total_str = first_match(r"Hard Disk:\s*\n\s*Total:\s+([\d,]+)\s*KB", perf_block)
    disk_gb      = _parse_kb(hd_total_str) / 1024 / 1024 if hd_total_str else 0.0

    dvm_block    = section_text(text, "### diag dvm device list")
    managed_m    = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
    licensed_m   = re.search(r"There are currently (\d+) devices/vdoms count for license", dvm_block)
    num_managed  = int(managed_m.group(1))  if managed_m  else 0
    num_licensed = int(licensed_m.group(1)) if licensed_m else 0

    info(f"Actual vCPU      : {vcpu_count if vcpu_count else 'not found'}"
         + (f"  (processors 0..{vcpu_count - 1})" if vcpu_count else ""))
    info(f"Actual RAM       : {ram_gb:.1f} GB")
    info(f"Actual Disk      : {disk_gb:.1f} GB")
    info(f"Devices managed  : {num_managed}  (licensed: {num_licensed})")
    print()

    current_tier = next((t for t in FMG_SIZING_TABLE if num_managed <= t[0]), FMG_SIZING_TABLE[-1])
    next_tier    = None
    for i, t in enumerate(FMG_SIZING_TABLE):
        if t == current_tier and i + 1 < len(FMG_SIZING_TABLE):
            next_tier = FMG_SIZING_TABLE[i + 1]
            break

    req_max, req_ram, req_cpu = current_tier
    info(f"Required tier : up to {req_max} devices/VDOMs  ->  "
         f"{req_cpu} vCPU, {req_ram} GB RAM,  {FMG_ABS_MIN_DISK_GB} GB disk (min)")
    if next_tier:
        info(f"Next tier     : up to {next_tier[0]} devices/VDOMs  ->  "
             f"{next_tier[2]} vCPU, {next_tier[1]} GB RAM,  {FMG_ABS_MIN_DISK_GB} GB disk (min)")
    print()

    pct = (num_managed / req_max * 100) if req_max else 0
    info(f"Device count usage: {num_managed} / {req_max} ({pct:.1f}% of current tier ceiling)")
    (warn if pct >= 80 else warn if pct >= 60 else ok)(
        f"Device count is at {pct:.0f}% of the {req_max}-device tier ceiling"
        + (" — approaching limit" if pct >= 80 else " — monitor growth" if pct >= 60
           else " — capacity is adequate"))
    print()

    # vCPU
    if vcpu_count < FMG_ABS_MIN_CPU:
        crit(f"vCPU: {vcpu_count} is BELOW the absolute minimum of {FMG_ABS_MIN_CPU} "
             f"(required {req_cpu} for up to {req_max} devices)")
    elif vcpu_count < req_cpu:
        crit(f"vCPU: {vcpu_count} is BELOW the required {req_cpu} for {num_managed} devices")
    elif next_tier and vcpu_count < next_tier[2] and pct >= 60:
        warn(f"vCPU: {vcpu_count} meets current tier but insufficient for next tier "
             f"({next_tier[2]} vCPU needed for up to {next_tier[0]} devices)")
    else:
        ok(f"vCPU: {vcpu_count} meets requirement ({req_cpu} vCPU for up to {req_max} devices)")

    # RAM
    if ram_gb < FMG_ABS_MIN_RAM_GB:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW the absolute minimum of {FMG_ABS_MIN_RAM_GB} GB")
    elif ram_gb < req_ram:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW the required {req_ram} GB for {num_managed} devices")
    elif ram_gb < req_ram * 1.1:
        warn(f"RAM: {ram_gb:.1f} GB meets minimum ({req_ram} GB) but headroom is tight")
    elif next_tier and ram_gb < next_tier[1] and pct >= 60:
        warn(f"RAM: {ram_gb:.1f} GB meets current tier but insufficient for next tier "
             f"({next_tier[1]} GB needed for up to {next_tier[0]} devices)")
    else:
        ok(f"RAM: {ram_gb:.1f} GB meets requirement ({req_ram} GB for up to {req_max} devices)")

    # Disk
    if disk_gb < FMG_ABS_MIN_DISK_GB:
        crit(f"Disk: {disk_gb:.1f} GB is BELOW the absolute minimum of {FMG_ABS_MIN_DISK_GB} GB")
    elif disk_gb < FMG_ABS_MIN_DISK_GB * 1.1:
        warn(f"Disk: {disk_gb:.1f} GB meets minimum ({FMG_ABS_MIN_DISK_GB} GB) but headroom is tight")
    else:
        ok(f"Disk: {disk_gb:.1f} GB meets the absolute minimum ({FMG_ABS_MIN_DISK_GB} GB)")


def check_cdb_upgrade(text: str):
    section("CDB Upgrade History (diag cdb upgrade summary)")

    block = section_text(text, "### diag cdb upgrade summary")
    if not block:
        warn("diag cdb upgrade summary section not found in file")
        return

    ver_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(v[\d.]+-build\d+[^\n]*?)$",
        re.MULTILINE,
    )
    entries = ver_pattern.findall(block)
    if not entries:
        warn("No version entries found in cdb upgrade summary")
        return

    info(f"CDB version chain ({len(entries)} entr{'y' if len(entries) == 1 else 'ies'}):")
    prev_ver, prev_tuple = None, None
    downgrade_found = False

    for ts, ver_raw in entries:
        ver       = ver_raw.strip()
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

        prev_ver, prev_tuple = ver, cur_tuple

    print()
    if downgrade_found:
        crit("Downgrade(s) detected in CDB version chain — investigate before proceeding")
    else:
        ok("No downgrades detected in CDB version chain")


def check_fds_sizing(text: str):
    section("FDS Sizing (closed network / FortiGuard Distribution Server)")

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    if "FortiAnalyzer" in platform_full:
        info("FortiAnalyzer detected — FDS sizing check not applicable")
        return

    info("Reference: docs.fortinet.com/document/fortimanager/7.6.0/best-practices/14860/")

    svc_block = section_text(text, "### diag fmupdate view-service-info fgd")
    if not svc_block:
        info("diag fmupdate view-service-info fgd section not found — skipping FDS check")
        return

    svc_lines     = [l.strip() for l in svc_block.splitlines() if ":" in l]
    enabled_svcs  = [l for l in svc_lines if l.endswith(": on")]
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

    for svc in enabled_svcs:
        ok(f"  Service active: {svc}")
    for svc in disabled_svcs:
        info(f"  Service off   : {svc}")
    print()

    FALLBACK_DB_SIZES = {
        "webfilter": 13.0, "iot": 18.0, "filequery": 5.0,
        "antispam": 0.5, "avquery": 0.5,
    }
    DBVER_MAP = {
        "wf": "webfilter", "iotm": "iot", "iotr": "iot", "iots": "iot",
        "fq": "filequery", "as1": "antispam", "as2": "antispam", "as4": "antispam",
        "av": "avquery", "av2": "avquery",
    }

    def parse_dbver_size(s):
        s = s.strip()
        if s.endswith("G"): return float(s[:-1])
        if s.endswith("M"): return float(s[:-1]) / 1024
        if s.endswith("K"): return float(s[:-1]) / 1024 / 1024
        return 0.0

    actual_db_sizes  = {}
    dbver_block      = section_text(text, "### diag fmupdate fgd-dbver")
    dbver_size_source = "Jan 2026 Fortinet doc estimates (DBs not yet downloaded)"

    if dbver_block:
        for line in dbver_block.splitlines():
            parts = line.split()
            if len(parts) < 2: continue
            code = parts[0].lower()
            if code not in DBVER_MAP: continue
            if parts[-1][-1] in ("G", "M", "K") and re.match(r"[\d.]+[GMK]$", parts[-1]):
                sz = parse_dbver_size(parts[-1])
                if sz > 0:
                    actual_db_sizes[DBVER_MAP[code]] = actual_db_sizes.get(DBVER_MAP[code], 0.0) + sz
        if actual_db_sizes:
            dbver_size_source = "actual sizes from diag fmupdate fgd-dbver"

    SVC_MAP = {
        "webfilter": re.compile(r"webfilter.*: on", re.IGNORECASE),
        "iot":       re.compile(r"iot.*: on", re.IGNORECASE),
        "filequery": re.compile(r"file query.*: on", re.IGNORECASE),
        "antispam":  re.compile(r"antispam.*: on", re.IGNORECASE),
        "avquery":   re.compile(r"antivirus query.*: on|outbreak.*: on", re.IGNORECASE),
    }

    mem_block        = section_text(text, "### Memory info")
    mem_total_kb_str = first_match(r"^MemTotal:\s+([\d]+)\s*kB", mem_block, re.MULTILINE)
    fmg_req_gb       = float(mem_total_kb_str) / 1024 / 1024 if mem_total_kb_str else 0.0

    enabled_db_total, active_dbs = 0.0, []
    for db_key, pattern in SVC_MAP.items():
        if any(pattern.search(l) for l in svc_lines):
            if db_key in actual_db_sizes:
                size  = actual_db_sizes[db_key]
                label = f"{db_key} ({size:.2f} GB — from fgd-dbver)"
            else:
                size  = FALLBACK_DB_SIZES[db_key]
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

    FDS_WORKER_TABLE = [
        (50, 1, "1-50 devices"), (1000, 10, "50-1000 devices"),
        (3000, 24, "1000-3000 devices"), (9999999, 24, "3000+ devices"),
    ]
    dvm_block = section_text(text, "### diag dvm device list")
    managed_m = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
    num_devices = int(managed_m.group(1)) if managed_m else 0

    fds_block = section_text(text, "config fmupdate fds-setting")
    maxwork_m = re.search(r"set\s+max-work\s+(\d+)", fds_block)
    max_work  = int(maxwork_m.group(1)) if maxwork_m else 1

    recommended_workers, recommended_label = 1, "1-50 devices"
    for threshold, workers, label in FDS_WORKER_TABLE:
        if num_devices <= threshold:
            recommended_workers, recommended_label = workers, label
            break

    info(f"Managed devices       : {num_devices}")
    info(f"Configured max-work   : {max_work}{' (default)' if not maxwork_m else ''}")
    info(f"Recommended max-work  : {recommended_workers}  (for {recommended_label})")
    print()

    if max_work < recommended_workers:
        crit(f"FDS workers: {max_work} is BELOW recommended {recommended_workers} for {num_devices} devices")
        crit(f"  Fix: config fmupdate fds-setting -> set max-work {recommended_workers}")
    elif max_work == recommended_workers:
        ok(f"FDS workers: {max_work} matches recommendation for {num_devices} devices")
    else:
        ok(f"FDS workers: {max_work} exceeds minimum recommendation ({recommended_workers}) for {num_devices} devices")
        if max_work > 24:
            warn("Note: no benefit to max-work above 24 per Fortinet docs")


def check_faz_lograte(text: str):
    section("FAZ Log Rate and Sizing")

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    platform_type = first_match(r"^Platform Type\s*:\s*(.+)$",      status_block, re.MULTILINE) or ""
    if "FortiAnalyzer" not in platform_full:
        info("FortiManager detected — FAZ log rate check not applicable")
        return

    is_vm = "-VM" in platform_type.upper()

    info("Reference: docs.fortinet.com/document/fortianalyzer-private-cloud/"
         "8.0.0/kvm-administration-guide/583600/minimum-system-requirements")

    limits_block = section_text(text, "### get system loglimits")
    peak_str     = first_match(r"^Peak Log Rate\s*:\s*(\d+)",     limits_block, re.MULTILINE)
    sust_str     = first_match(r"^Sustained Log Rate\s*:\s*(\d+)", limits_block, re.MULTILINE)
    gb_str       = first_match(r"^GB/day\s*:\s*(\d+)",            limits_block, re.MULTILINE)
    peak_rate    = int(peak_str) if peak_str else None
    sustained    = int(sust_str) if sust_str else None

    if limits_block:
        info(f"Licensed GB/day          : {gb_str or 'N/A'}")
        info(f"Licensed Peak Log Rate   : {peak_rate or 'N/A'} logs/sec")
        info(f"Licensed Sustained Rate  : {sustained or 'N/A'} logs/sec")
    else:
        warn("get system loglimits section not found")
    print()

    lograte_block = section_text(text, "### diag fortilogd lograte")
    actual_rate   = None
    if lograte_block:
        for pattern in [r"last 60 seconds:\s*([\d.]+)",
                        r"last 30 seconds:\s*([\d.]+)",
                        r"last 5 seconds:\s*([\d.]+)"]:
            m = re.search(pattern, lograte_block, re.IGNORECASE)
            if m:
                actual_rate = float(m.group(1))
                break
        info(f"Actual receive rate      : {actual_rate if actual_rate is not None else 'N/A'} logs/sec")
    else:
        info("diag fortilogd lograte   : section not found")
    print()

    lf_idx = text.find("config system log-forward")
    if lf_idx != -1:
        lf_end   = text.find("\nend\n", lf_idx)
        lf_block = text[lf_idx:lf_end + 5] if lf_end != -1 else ""
        num_fwds = len(re.findall(r"^\s{4}edit\s+\d+", lf_block, re.MULTILINE))
    else:
        num_fwds = 0

    info(f"Log forwarders configured: {num_fwds}")

    logfwd_diag = section_text(text, "### diagnose test application logfwd 4")
    if num_fwds > 0 and logfwd_diag:
        lag_matches = re.findall(
            r"\*\*\s+Loader:\s+ld-(\S+).*?lag-behind=([\d.]+)%\s+\((\d+)\)",
            logfwd_diag, re.DOTALL)
        for fwd_name, lag_pct, lag_bytes in lag_matches:
            pct = float(lag_pct)
            msg = f"  Forwarder {fwd_name}: lag-behind {lag_pct}% ({lag_bytes} bytes)"
            (crit if pct > 5 else warn if pct > 1 else ok)(msg)

        server_matches = re.findall(
            r"\*\*\s+Server#\d+:\s+(\S+).*?log/sec:\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
            logfwd_diag, re.DOTALL)
        for srv, r5, r30, r60 in server_matches:
            info(f"  Server {srv}: log/sec last 5s={r5} 30s={r30} 60s={r60}")
    print()

    if actual_rate is not None:
        eff_rate = actual_rate * (1 + num_fwds)
        if num_fwds > 0:
            info(f"Effective sizing rate    : {actual_rate:.0f} x (1 + {num_fwds}) = {eff_rate:.0f} logs/sec")
        else:
            info(f"Effective sizing rate    : {eff_rate:.0f} logs/sec (no forwarders)")
    else:
        eff_rate = None
        info("Effective sizing rate    : cannot calculate (actual rate not available)")

    if actual_rate is not None and peak_rate is not None:
        print()
        if actual_rate > peak_rate:
            crit(f"Actual rate {actual_rate:.0f} EXCEEDS licensed Peak Log Rate of {peak_rate} logs/sec")
        elif actual_rate > peak_rate * 0.8:
            warn(f"Actual rate {actual_rate:.0f} is within 20% of licensed Peak Log Rate ({peak_rate} logs/sec)")
        else:
            ok(f"Actual rate {actual_rate:.0f} is within licensed Peak Log Rate ({peak_rate} logs/sec)")

    if not is_vm:
        info("Hardware appliance — VM sizing table check not applicable")
        return

    if eff_rate is None:
        warn("Cannot perform VM sizing check — actual log rate not available")
        return

    cpu_block  = section_text(text, "### diag system print cpuinfo")
    processors = re.findall(r"^processor\s*:\s*(\d+)", cpu_block, re.MULTILINE)
    vcpu_count = max(int(p) for p in processors) + 1 if processors else 0
    mem_block  = section_text(text, "### Memory info")
    mem_str    = first_match(r"^MemTotal:\s+([\d]+)\s*kB", mem_block, re.MULTILINE)
    ram_gb     = float(mem_str) / 1024 / 1024 if mem_str else 0.0

    tier = next((t for t in FAZ_SIZING_TABLE if eff_rate <= t[0]), FAZ_SIZING_TABLE[-1])
    req_rate, req_ram, req_cpu, req_iops = tier
    print()
    info(f"Required sizing tier     : up to {req_rate} logs/sec -> "
         f"{req_cpu} vCPU, {req_ram} GB RAM, {req_iops} IOPS")

    if vcpu_count and vcpu_count < req_cpu:
        crit(f"vCPU: {vcpu_count} is BELOW required {req_cpu} for {eff_rate:.0f} logs/sec effective rate")
    elif vcpu_count:
        ok(f"vCPU: {vcpu_count} meets requirement ({req_cpu} needed for this tier)")

    if ram_gb and ram_gb < req_ram:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW required {req_ram} GB for {eff_rate:.0f} logs/sec effective rate")
    elif ram_gb:
        ok(f"RAM: {ram_gb:.1f} GB meets requirement ({req_ram} GB needed for this tier)")

    info(f"IOPS requirement         : {req_iops} IOPS — verify storage performance separately")


def check_klog(text: str):
    section("Kernel Log (diag debug klog)")

    block = section_text(text, "### diag debug klog")
    if not block:
        warn("diag debug klog section not found in file")
        return

    boot_ts_pattern = re.compile(r"^@@@(.+)$")
    uptime_pattern  = re.compile(r"^\s*<?[^>]*>?\s*\[\s*([\d.]+)\]")
    oom_pattern     = re.compile(
        r"out.of.memory|oom.killer|oom-kill(?:er)?|killed process"
        r"|oom_score|cannot allocate memory", re.IGNORECASE)
    fsck_pattern    = re.compile(
        r"e2fsck|fsck|maximal mount count reached"
        r"|ext[234]-fs.{0,10}error|ext[234]-fs.{0,10}warning"
        r"|journal.*abort|i/o error.*block|bad block"
        r"|filesystem.*corrupt|remount.*read.only", re.IGNORECASE)

    def resolve_time(boot_str, uptime_secs):
        for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"):
            try:
                dt = datetime.strptime(boot_str.strip(), fmt)
                return (dt + timedelta(seconds=uptime_secs)).strftime("%a %b %d %H:%M:%S %Y")
            except ValueError:
                pass
        return boot_str.strip()

    current_boot = None
    oom_hits, fsck_hits = [], []

    for line in block.splitlines():
        m = boot_ts_pattern.match(line)
        if m:
            current_boot = m.group(1)
            continue
        is_oom  = bool(oom_pattern.search(line))
        is_fsck = bool(fsck_pattern.search(line))
        if not (is_oom or is_fsck):
            continue
        wall = current_boot or "unknown boot time"
        um   = uptime_pattern.match(line)
        if um and current_boot:
            try:
                wall = resolve_time(current_boot, float(um.group(1)))
            except Exception:
                pass
        if is_oom:  oom_hits.append((wall, line.strip()))
        if is_fsck: fsck_hits.append((wall, line.strip()))

    if oom_hits:
        crit(f"Out-of-memory events found: {len(oom_hits)}")
        for wall, line in oom_hits[:10]:
            crit(f"  [{wall}]  {line[:100]}")
        if len(oom_hits) > 10:
            crit(f"  ... and {len(oom_hits) - 10} more")
    else:
        ok("No out-of-memory events found in kernel log")

    if fsck_hits:
        errors   = [(w, l) for w, l in fsck_hits
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


CHECKS = [
    ("System Status",        check_system_status),
    ("VM License",           check_vm_license),
    ("Performance",          check_performance),
    ("Sizing Adequacy",      check_sizing),
    ("CDB Upgrade History",  check_cdb_upgrade),
    ("FDS Sizing",           check_fds_sizing),
    ("FAZ Log Rate",         check_faz_lograte),
    ("Kernel Log",           check_klog),
]


# ----------
# MAIN
# ----------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <tac_report_file>")
        sys.exit(1)

    path = sys.argv[1]
    text = load(path)

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    platform_type = first_match(r"^Platform Type\s*:\s*(.+)$",      status_block, re.MULTILINE) or ""

    product = "FortiAnalyzer" if "FortiAnalyzer" in platform_full else "FortiManager"
    is_vm   = "-VM" in platform_type.upper()

    if is_vm:
        plat_upper = platform_full.upper()
        if   "KVM"    in plat_upper: vm_plat = "KVM"
        elif "XEN"    in plat_upper: vm_plat = "XEN"
        elif "HV"     in plat_upper: vm_plat = "Hyper-V"
        elif "AWS"    in plat_upper: vm_plat = "AWS"
        elif "AZURE"  in plat_upper: vm_plat = "Azure"
        elif "GCP"    in plat_upper: vm_plat = "GCP"
        else:                         vm_plat = "VM"
        klog_block = section_text(text, "### diag debug klog")
        hv_m = re.search(r"Hypervisor detected:\s*(\S+)", klog_block, re.IGNORECASE)
        if hv_m:
            hv_map = {"vmware": "VMware", "kvm": "KVM", "xen": "XEN",
                      "hyperv": "Hyper-V", "hyper-v": "Hyper-V",
                      "microsoft": "Hyper-V", "aws": "AWS",
                      "azure": "Azure", "google": "GCP"}
            vm_plat = hv_map.get(hv_m.group(1).lower().rstrip(".,"), hv_m.group(1))
        plat_label = f"on {vm_plat}"
    else:
        plat_label = "Hardware Appliance"

    title_line = f"{product} TAC Report Health Check  [{platform_type} {plat_label}]"

    print()
    print(title_line)
    print("by Farhan Ahmed - ETAC-AMER")
    print("-" * max(40, len(title_line)))
    print(f"  File: {path}")
    print(f"  Size: {len(text):,} chars  /  {text.count(chr(10)):,} lines")

    import io, contextlib

    results = {}
    for label, fn in CHECKS:
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                fn(text)
            output = buf.getvalue()
            print(output, end="")
            results[label] = (output.count("[CRIT]"), output.count("[WARN]"), None)
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