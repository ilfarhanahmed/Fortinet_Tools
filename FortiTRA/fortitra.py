# !/usr/bin/env python3
"""
FortiManager / FortiAnalyzer TAC Report — Sizing Tool
by Farhan Ahmed - ETAC-AMER

Checks:
  - System Status
  - Sizing (FMG VM / FAZ VM / Hardware)
  - FDS Sizing (FMG only)

Sizing references:
  FMG: docs.fortinet.com/document/fortimanager-private-cloud/7.6.0/
       kvm-administration-guide/583600/minimum-system-requirements
  FAZ: docs.fortinet.com/document/fortianalyzer-private-cloud/8.0.0/
       kvm-administration-guide/583600/minimum-system-requirements
"""

import re
import sys
from pathlib import Path
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Sizing tables
# ---------------------------------------------------------------------------

# FMG VM: (max_devices_vdoms, min_ram_gb, min_cpu_cores)
FMG_SIZING_TABLE = [
    (100,    16,  4),
    (300,    16,  6),
    (1200,   32,  6),
    (4000,   64, 16),
    (10000, 128, 24),
]
FMG_ABS_MIN_CPU     = 4
FMG_ABS_MIN_RAM_GB  = 16
FMG_ABS_MIN_DISK_GB = 500

# FAZ VM: (analytic_rate, min_ram_gb, min_cpu, min_iops)
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
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)

def ok(msg): print(f"  [OK  ] {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def crit(msg): print(f"  [CRIT] {msg}")
def info(msg): print(f"  [INFO] {msg}")


# -----------
# Helpers
# -----------

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


def _get_vcpu_ram_disk(text: str):
    """Return (vcpu_count, ram_gb, disk_gb) from the TAC file."""
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

    return vcpu_count, ram_gb, disk_gb


# ------------------
# System Status
# ------------------

def check_system_status(text: str):
    section("System Status")
    block = section_text(text, "### get system status")

    fields = {
        "Platform Full Name":  "Platform",
        "Version":  "Version",
        "Serial Number":"Serial",
        "Hostname":  "Hostname",
        "HA Mode": "HA Mode",
        "Disk Usage":"Disk Usage",
        "License Status": "License",
        "Image Signature":   "Image Signature",
        "Admin Domain Configuration": "ADOM Config",
        "Max Number of Admin Domains":"Max ADOMs",
        "FIPS Mode":  "FIPS Mode",
    }

    rows = []
    for key, label in fields.items():
        val = first_match(rf"^{re.escape(key)}\s*:\s*(.+)$", block, re.MULTILINE)
        if val is not None:
            rows.append((label, val))

    col_width = max(len(label) for label, _ in rows) if rows else 0
    for label, val in rows:
        print(f"  {label:<{col_width}}  :  {val}")


# ------------------
# FMG Sizing
# ------------------

def _check_fmg_sizing(text: str, platform_type: str, is_vm: bool):
    dvm_block    = section_text(text, "### diag dvm device list")
    managed_m    = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
    licensed_m   = re.search(r"There are currently (\d+) devices/vdoms count for license", dvm_block)
    num_managed  = int(managed_m.group(1))  if managed_m  else 0
    num_licensed = int(licensed_m.group(1)) if licensed_m else 0

    if not is_vm:
        info(f"Hardware appliance ({platform_type}) — VM minimum resource checks do not apply")
        info(f"Refer to the {platform_type} hardware datasheet for specifications")
        info(f"Devices managed  : {num_managed}  (licensed: {num_licensed})")
        return

    info("Reference: docs.fortinet.com/document/fortimanager-private-cloud/"
         "7.6.0/kvm-administration-guide/583600/minimum-system-requirements")
    print()

    vcpu_count, ram_gb, disk_gb = _get_vcpu_ram_disk(text)

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
    info(f"Required tier    : up to {req_max} devices/VDOMs  ->  "
         f"{req_cpu} vCPU, {req_ram} GB RAM, {FMG_ABS_MIN_DISK_GB} GB disk (min)")
    if next_tier:
        info(f"Next tier        : up to {next_tier[0]} devices/VDOMs  ->  "
             f"{next_tier[2]} vCPU, {next_tier[1]} GB RAM, {FMG_ABS_MIN_DISK_GB} GB disk (min)")
    print()

    pct = (num_managed / req_max * 100) if req_max else 0
    info(f"Device count usage: {num_managed} / {req_max} ({pct:.1f}% of current tier ceiling)")
    (crit if pct >= 80 else warn if pct >= 60 else ok)(
        f"Device count at {pct:.0f}% of {req_max}-device tier ceiling"
        + (" — approaching limit, plan upgrade" if pct >= 80
           else " — monitor growth" if pct >= 60 else " — capacity is adequate"))
    print()

    # vCPU
    if not vcpu_count:
        warn("vCPU: could not determine from file")
    elif vcpu_count < FMG_ABS_MIN_CPU:
        crit(f"vCPU: {vcpu_count} is BELOW the absolute minimum of {FMG_ABS_MIN_CPU} "
             f"(required {req_cpu} for up to {req_max} devices)")
    elif vcpu_count < req_cpu:
        crit(f"vCPU: {vcpu_count} is BELOW the required {req_cpu} for {num_managed} devices "
             f"(tier: up to {req_max} devices requires {req_cpu} vCPU)")
    elif next_tier and vcpu_count < next_tier[2] and pct >= 60:
        warn(f"vCPU: {vcpu_count} meets current tier but insufficient for next tier "
             f"({next_tier[2]} vCPU needed for up to {next_tier[0]} devices)")
    else:
        ok(f"vCPU: {vcpu_count} meets requirement ({req_cpu} vCPU for up to {req_max} devices)")

    # RAM
    if not ram_gb:
        warn("RAM: could not determine from file")
    elif ram_gb < FMG_ABS_MIN_RAM_GB:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW the absolute minimum of {FMG_ABS_MIN_RAM_GB} GB "
             f"(required {req_ram} GB for up to {req_max} devices)")
    elif ram_gb < req_ram:
        crit(f"RAM: {ram_gb:.1f} GB is BELOW the required {req_ram} GB for {num_managed} devices "
             f"(tier: up to {req_max} devices requires {req_ram} GB)")
    elif ram_gb < req_ram * 1.1:
        warn(f"RAM: {ram_gb:.1f} GB meets minimum ({req_ram} GB) but headroom is tight")
    elif next_tier and ram_gb < next_tier[1] and pct >= 60:
        warn(f"RAM: {ram_gb:.1f} GB meets current tier but insufficient for next tier "
             f"({next_tier[1]} GB needed for up to {next_tier[0]} devices)")
    else:
        ok(f"RAM: {ram_gb:.1f} GB meets requirement ({req_ram} GB for up to {req_max} devices)")

    # Disk
    if not disk_gb:
        warn("Disk: could not determine from file")
    elif disk_gb < FMG_ABS_MIN_DISK_GB:
        crit(f"Disk: {disk_gb:.1f} GB is BELOW the absolute minimum of {FMG_ABS_MIN_DISK_GB} GB")
    elif disk_gb < FMG_ABS_MIN_DISK_GB * 1.1:
        warn(f"Disk: {disk_gb:.1f} GB meets minimum ({FMG_ABS_MIN_DISK_GB} GB) but headroom is tight")
    else:
        ok(f"Disk: {disk_gb:.1f} GB meets the absolute minimum ({FMG_ABS_MIN_DISK_GB} GB)")


# ------------------
# FAZ Sizing
# ------------------

def _check_faz_sizing(text: str, platform_type: str, is_vm: bool):
    info("Reference: docs.fortinet.com/document/fortianalyzer-private-cloud/"
         "8.0.0/kvm-administration-guide/583600/minimum-system-requirements")
    print()

    # Licensed limits
    limits_block = section_text(text, "### get system loglimits")
    peak_str     = first_match(r"^Peak Log Rate\s*:\s*(\d+)",      limits_block, re.MULTILINE)
    sust_str     = first_match(r"^Sustained Log Rate\s*:\s*(\d+)", limits_block, re.MULTILINE)
    gb_str       = first_match(r"^GB/day\s*:\s*(\d+)",             limits_block, re.MULTILINE)
    peak_rate    = int(peak_str) if peak_str else None
    sustained    = int(sust_str) if sust_str else None

    if limits_block:
        info(f"Licensed GB/day          : {gb_str or 'N/A'}")
        info(f"Licensed Peak Log Rate   : {peak_rate or 'N/A'} logs/sec")
        info(f"Licensed Sustained Rate  : {sustained or 'N/A'} logs/sec")
    else:
        warn("get system loglimits: section not found")
    print()

    # Actual log rate
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

    # Log forwarders — parse config block for forwarder names
    lf_idx = text.find("config system log-forward")
    num_fwds     = 0
    fwd_names    = []
    if lf_idx != -1:
        lf_end   = text.find("\nend\n", lf_idx)
        lf_block = text[lf_idx:lf_end + 5] if lf_end != -1 else ""
        # Extract server-name per edit block
        edit_blocks = re.split(r"\n\s{4}edit\s+\d+", lf_block)[1:]
        for eb in edit_blocks:
            name_m = re.search(r'set\s+server-name\s+"([^"]+)"', eb)
            if name_m:
                fwd_names.append(name_m.group(1))
        num_fwds = len(fwd_names)

    info(f"Log forwarders configured: {num_fwds}")

    # Parse logfwd 4 — build per-forwarder dict
    logfwd_diag = section_text(text, "### diagnose test application logfwd 4")
    # Strip ANSI escape codes
    logfwd_clean = re.sub(r"\x1b\[[0-9;]*m", "", logfwd_diag)

    print()

    # Effective rate
    if actual_rate is not None:
        eff_rate = actual_rate * (1 + num_fwds)
        if num_fwds > 0:
            info(f"Effective sizing rate    : {actual_rate:.0f} x (1 + {num_fwds}) = {eff_rate:.0f} logs/sec")
        else:
            info(f"Effective sizing rate    : {eff_rate:.0f} logs/sec (no forwarders)")
    else:
        eff_rate = None
        info("Effective sizing rate    : cannot calculate (actual rate not available)")

    # Compare against licensed peak
    if actual_rate is not None and peak_rate is not None:
        print()
        if actual_rate > peak_rate:
            crit(f"Actual rate {actual_rate:.0f} EXCEEDS licensed Peak Log Rate of {peak_rate} logs/sec")
        elif actual_rate > peak_rate * 0.8:
            warn(f"Actual rate {actual_rate:.0f} is within 20% of Peak Log Rate ({peak_rate} logs/sec)")
        else:
            ok(f"Actual rate {actual_rate:.0f} is within licensed Peak Log Rate ({peak_rate} logs/sec)")

    # Hardware vs VM sizing
    if not is_vm:
        print()
        info(f"Hardware appliance ({platform_type}) — VM minimum resource checks do not apply")
        info(f"Refer to the {platform_type} hardware datasheet for disk and IOPS specifications")
        return

    if eff_rate is None:
        warn("Cannot perform VM sizing check — actual log rate not available")
        return

    vcpu_count, ram_gb, _ = _get_vcpu_ram_disk(text)
    tier = next((t for t in FAZ_SIZING_TABLE if eff_rate <= t[0]), FAZ_SIZING_TABLE[-1])
    req_rate, req_ram, req_cpu, req_iops = tier

    print()
    info(f"Required VM sizing tier  : up to {req_rate} logs/sec -> "
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


# ------------------
# Combined Sizing
# ------------------

def check_sizing(text: str):
    section("Sizing Check")

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    platform_type = first_match(r"^Platform Type\s*:\s*(.+)$",      status_block, re.MULTILINE) or ""
    is_vm         = "-VM" in platform_type.upper()
    is_faz        = "FortiAnalyzer" in platform_full

    if is_faz:
        _check_faz_sizing(text, platform_type, is_vm)
    else:
        _check_fmg_sizing(text, platform_type, is_vm)


# ------------------
# FDS Sizing (FMG only)
# ------------------

def check_fds_sizing(text: str):
    section("FDS Sizing (closed network / FortiGuard Distribution Server)")

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    if "FortiAnalyzer" in platform_full:
        return  # silently skip — caller excludes FAZ

    info("Reference: docs.fortinet.com/document/fortimanager/7.6.0/best-practices/14860/")

    svc_block = section_text(text, "### diag fmupdate view-service-info fgd")
    if not svc_block:
        info("diag fmupdate view-service-info fgd not found — FMG is not acting as a local FortiGuard server")
        return

    svc_lines    = [l.strip() for l in svc_block.splitlines() if ":" in l]
    enabled_svcs = [l for l in svc_lines if l.endswith(": on")]
    disabled_svcs = [l for l in svc_lines if l.endswith(": off")]

    info(f"FGD rating services enabled : {len(enabled_svcs)}")
    print()

    if not enabled_svcs:
        ok("No FGD rating services enabled — FMG is NOT acting as a local FortiGuard server")
        return

    for svc in enabled_svcs:
        ok(f"  Service active: {svc}")
    for svc in disabled_svcs:
        info(f"  Service off   : {svc}")
    print()

    FALLBACK_DB_SIZES = {
        "webfilter": 13.0, "iot": 18.0, "filequery": 5.0,
        "antispam": 0.5,   "avquery": 0.5,
    }
    DBVER_MAP = {
        "wf": "webfilter", "iotm": "iot", "iotr": "iot", "iots": "iot",
        "fq": "filequery",  "as1": "antispam", "as2": "antispam", "as4": "antispam",
        "av": "avquery",    "av2": "avquery",
    }

    def parse_dbver_size(s):
        s = s.strip()
        if s.endswith("G"): return float(s[:-1])
        if s.endswith("M"): return float(s[:-1]) / 1024
        if s.endswith("K"): return float(s[:-1]) / 1024 / 1024
        return 0.0

    actual_db_sizes   = {}
    dbver_block       = section_text(text, "### diag fmupdate fgd-dbver")
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
        "webfilter": re.compile(r"webfilter.*: on",  re.IGNORECASE),
        "iot":       re.compile(r"iot.*: on",        re.IGNORECASE),
        "filequery": re.compile(r"file query.*: on", re.IGNORECASE),
        "antispam":  re.compile(r"antispam.*: on",   re.IGNORECASE),
        "avquery":   re.compile(r"antivirus query.*: on|outbreak.*: on", re.IGNORECASE),
    }

    mem_block        = section_text(text, "### Memory info")
    mem_total_kb_str = first_match(r"^MemTotal:\s+([\d]+)\s*kB", mem_block, re.MULTILINE)
    fmg_req_gb       = float(mem_total_kb_str) / 1024 / 1024 if mem_total_kb_str else 0.0

    enabled_db_total, active_dbs = 0.0, []
    for db_key, pattern in SVC_MAP.items():
        if any(pattern.search(l) for l in svc_lines):
            size  = actual_db_sizes.get(db_key, FALLBACK_DB_SIZES[db_key])
            label = (f"{db_key} ({size:.2f} GB — from fgd-dbver)"
                     if db_key in actual_db_sizes
                     else f"{db_key} ({size:.1f} GB — Jan 2026 estimate)")
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
        crit(f"RAM: {fmg_req_gb:.1f} GB is BELOW the FDS-adjusted requirement of {vm_total_required:.1f} GB")
        crit(f"  Additional RAM needed: {vm_total_required - fmg_req_gb:.1f} GB")
        crit("  Risk: high I/O wait, degraded performance, possible OOM")
    else:
        ok(f"RAM: {fmg_req_gb:.1f} GB meets FDS-adjusted requirement of {vm_total_required:.1f} GB")
    print()

    FDS_WORKER_TABLE = [
        (50,      1,  "1-50 devices"),
        (1000,   10,  "50-1000 devices"),
        (3000,   24,  "1000-3000 devices"),
        (9999999, 24, "3000+ devices"),
    ]
    dvm_block   = section_text(text, "### diag dvm device list")
    managed_m   = re.search(r"There are currently (\d+) devices/vdoms managed", dvm_block)
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


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <tac_report_file>")
        sys.exit(1)

    path = sys.argv[1]
    text = load(path)

    status_block  = section_text(text, "### get system status")
    platform_full = first_match(r"^Platform Full Name\s*:\s*(.+)$", status_block, re.MULTILINE) or ""
    platform_type = first_match(r"^Platform Type\s*:\s*(.+)$",      status_block, re.MULTILINE) or ""

    product  = "FortiAnalyzer" if "FortiAnalyzer" in platform_full else "FortiManager"
    is_vm    = "-VM" in platform_type.upper()
    is_faz   = "FortiAnalyzer" in platform_full

    if is_vm:
        plat_upper = platform_full.upper()
        if   "KVM"   in plat_upper: vm_plat = "KVM"
        elif "XEN"   in plat_upper: vm_plat = "XEN"
        elif "HV"    in plat_upper: vm_plat = "Hyper-V"
        elif "AWS"   in plat_upper: vm_plat = "AWS"
        elif "AZURE" in plat_upper: vm_plat = "Azure"
        elif "GCP"   in plat_upper: vm_plat = "GCP"
        else:                        vm_plat = "VM"
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

    title_line = f"{product} Sizing Tool  [{platform_type} {plat_label}]"
    print()
    print(title_line)
    print("by Farhan Ahmed - ETAC-AMER")
    print("-" * max(40, len(title_line)))
    print(f"  File: {Path(path).name}")

    checks_to_run = [check_system_status, check_sizing]
    if not is_faz:
        checks_to_run.append(check_fds_sizing)

    for fn in checks_to_run:
        fn(text)

    print()


if __name__ == "__main__":
    main()
