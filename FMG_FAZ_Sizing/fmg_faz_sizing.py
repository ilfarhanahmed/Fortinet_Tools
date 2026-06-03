#!/usr/bin/env python3

"""
FortiManager / FortiAnalyzer TAC Sizing Tool
Author: Farhan Ahmed - www.farhan.ch

This tool analyzes FortiManager (FMG) and FortiAnalyzer (FAZ)
TAC reports (txt, log, tar.gz) and validates system sizing
based on Fortinet recommended deployment guidelines.

Use:
# py fmg_faz_sizing.py <file>

Checks Performed
----------------

1. System Status
- Platform information
- Firmware version
- Serial number
- Hostname
- HA mode
- ADOM configuration
- FIPS mode
- License status

2. FMG Sizing
- Managed device count
- VM CPU / RAM / Disk validation
- Tier utilization check

3. FAZ Sizing
- Licensed log rates
- Actual log receive rate
- Forwarder impact calculation
- Effective sizing rate
- VM CPU / RAM / Disk validation
- Required storage IOPS reference

4. FDS Sizing (FMG Only)
- FortiGuard Distribution Server detection
- Enabled rating services
- FDS RAM requirement calculation
- max-work recommendation validation

Sizing References
-----------------
FMG:
https://docs.fortinet.com/document/fortimanager-private-cloud/8.0.0/kvm-administration-guide/583600/minimum-system-requirements

FAZ:
https://docs.fortinet.com/document/fortianalyzer-private-cloud/8.0.0/kvm-administration-guide/583600/minimum-system-requirements

Hardware Datasheets:
https://docs.fortinet.com/product/fortimanager/hardware
https://docs.fortinet.com/product/fortianalyzer/hardware


"""

import argparse
import re
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


# ==============
# PRINT HELPERS
# ==============

def section(title):
    print("\n\n" + "=" * 70)
    print(title)
    print("=" * 70)
    print()


def ok(msg):
    print(f"[OK] {msg}")


def warn(msg):
    print(f"[WARN] {msg}")


def crit(msg):
    print(f"[CRIT] {msg}")


def info(msg):
    print(f"[INFO] {msg}")


def blank():
    print()


# =============
# SIZING TABLES
# =============

# devices, ram gb, cpu
FMG_SIZING = [
    (100, 16, 4),
    (300, 16, 6),
    (1200, 32, 6),
    (4000, 64, 16),
    (10000, 128, 24),
]

# logs/sec, ram gb, cpu, iops
FAZ_SIZING = [
    (3000, 16, 4, 300),
    (4000, 16, 4, 400),
    (5000, 16, 4, 500),
    (6000, 16, 8, 600),
    (7000, 16, 8, 700),
    (8000, 16, 8, 800),
    (9000, 16, 8, 900),
    (10000, 16, 8, 1000),
    (20000, 32, 16, 2000),
    (30000, 32, 16, 3000),
    (40000, 64, 32, 4000),
    (50000, 64, 32, 5000),
]

RECOMMENDATIONS = []

VM_RESOURCE_TOLERANCE_PERCENT = 5
DISK_REQUIREMENT_GB = 500

FMG_MIN_RESOURCE_URL = (
    "https://docs.fortinet.com/document/fortimanager-private-cloud/"
    "8.0.0/kvm-administration-guide/583600/"
    "minimum-system-requirements"
)

FAZ_MIN_RESOURCE_URL = (
    "https://docs.fortinet.com/document/fortianalyzer-private-cloud/"
    "8.0.0/kvm-administration-guide/583600/"
    "minimum-system-requirements"
)

FMG_CLOUD_LIMITATION_URL = (
    "https://docs.fortinet.com/document/fortimanager-cloud/"
    "7.6.6/release-notes/865961/"
    "limitations-of-fortimanager-cloud"
)

FAZ_CLOUD_LIMITATION_URL = (
    "https://docs.fortinet.com/document/fortianalyzer-cloud/"
    "7.6.6/release-notes/407448/"
    "limitations-of-fortianalyzer-cloud"
)

FDS_SIZING_URL = (
    "https://docs.fortinet.com/document/fortimanager/"
    "8.0.0/best-practices/14860/"
    "fortimanager-performance-and-sizing-in-closed-networks"
)


# =============
# FILE HELPERS
# =============

def recommend(msg):
    msg = msg.strip()

    if msg not in RECOMMENDATIONS:
        RECOMMENDATIONS.append(msg)


def remove_recommendation(pattern):
    regex = re.compile(pattern, re.IGNORECASE)
    RECOMMENDATIONS[:] = [
        item for item in RECOMMENDATIONS
        if not regex.search(item)
    ]


def load_file(path):
    try:
        text = Path(path).read_text(
            encoding="utf-8",
            errors="replace"
        )

        text = re.sub(
            r"\x1b\[[0-9;]*m",
            "",
            text
        )

        return text

    except FileNotFoundError:
        crit(f"File not found: {path}")
        sys.exit(1)


# Section from TAC report ###
def get_section(text, start_text):
    start = text.find(start_text)

    if start == -1:
        return ""

    start += len(start_text)
    end = text.find("### ", start)

    if end == -1:
        return text[start:]

    return text[start:end]


def get_any_section(text, start_texts):
    for start_text in start_texts:
        section_text = get_section(text, start_text)

        if section_text.strip():
            return section_text

    return ""


# config block
def get_config_block(text, start_text):
    start = text.find(start_text)

    if start == -1:
        return ""

    lines = text[start:].splitlines()

    depth = 0
    collected = []

    for line in lines:
        stripped = line.strip()

        collected.append(line)

        # entering config block
        if stripped.startswith("config "):
            depth += 1

        # leaving config block
        elif stripped == "end":
            depth -= 1

            # reached original config end
            if depth == 0:
                break

    return "\n".join(collected)


def find_value(pattern, text):
    match = re.search(pattern, text, re.MULTILINE)

    if match:
        return match.group(1).strip()

    return None


def kb_to_gb(kb):
    kb = kb.replace(",", "")
    return float(kb) / 1024 / 1024


def get_required_tier(value, table):
    for row in table:
        if value <= row[0]:
            return row

    return table[-1]


def within_tolerance(actual, required):
    minimum_allowed = required * (
        1 - VM_RESOURCE_TOLERANCE_PERCENT / 100
    )

    return actual >= minimum_allowed


def is_archive(path):
    name = Path(path).name.lower()

    return (
        name.endswith(".tar.gz")
        or name.endswith(".tgz")
        or name.endswith(".tar")
        or name.endswith(".zip")
        or name.endswith(".gz")
    )


def safe_extract_tar(tar, output_dir):
    output_dir = Path(output_dir).resolve()

    for member in tar.getmembers():
        member_path = (output_dir / member.name).resolve()

        if not str(member_path).startswith(str(output_dir)):
            raise RuntimeError(
                f"Unsafe path in archive: {member.name}"
            )

    try:
        tar.extractall(output_dir, filter="data")
    except TypeError:
        tar.extractall(output_dir)


def extract_archive(path, output_dir):
    path = Path(path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if path.name.lower().endswith(".zip"):
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(output_dir)

    else:
        with tarfile.open(path, "r:*") as tf:
            safe_extract_tar(tf, output_dir)

    return [
        item for item in output_dir.rglob("*")
        if item.is_file()
    ]


def command_name_from_path(path):
    name = path.stem
    name = re.sub(r"^\d+_", "", name)
    return name


def build_combined_tac_report(extracted_files, output_file):
    command_files = []
    fallback_files = []

    for extracted_file in extracted_files:
        path = Path(extracted_file)

        if not path.is_file():
            continue

        if path.suffix.lower() not in [".log", ".txt"]:
            continue

        fallback_files.append(path)

        if re.match(r"^\d+_", path.name):
            command_files.append(path)

    if not command_files:
        command_files = fallback_files

    if not command_files:
        return None

    def sort_key(path):
        match = re.match(r"^(\d+)_", path.name)

        if match:
            return int(match.group(1))

        return 999999

    output_file = Path(output_file)

    with open(output_file, "w", encoding="utf-8", errors="ignore") as out:
        for command_file in sorted(command_files, key=sort_key):
            command = command_name_from_path(command_file)

            out.write("\n\n")
            out.write(f"### {command}\n\n")

            try:
                with open(command_file, "r", encoding="utf-8", errors="ignore") as fh:
                    out.write(fh.read())
            except OSError:
                continue

            out.write("\n")

    return output_file


def load_input_file(path, save_combined=None):
    path = Path(path)

    if not is_archive(path):
        return load_file(path), path.name

    with tempfile.TemporaryDirectory() as temp_dir:
        extract_dir = Path(temp_dir) / "extracted"
        extracted_files = extract_archive(path, extract_dir)

        if save_combined:
            combined_file = Path(save_combined)
        else:
            combined_file = Path(temp_dir) / "combined_tac_report.log"

        combined_file = build_combined_tac_report(
            extracted_files,
            combined_file
        )

        if not combined_file:
            crit("No TAC command log files found inside archive")
            sys.exit(1)

        text = load_file(combined_file)

    return text, path.name


# ==================
# PRODUCT DETECTION
# ==================

def detect_product(text):
    status = get_section(
        text,
        "### get system status"
    )

    platform_full = find_value(
        r"Platform Full Name\s*:\s*(.+)",
        status
    ) or ""

    platform_type = find_value(
        r"Platform Type\s*:\s*(.+)",
        status
    ) or ""

    all_text = f"{platform_full} {platform_type}".upper()

    vm_words = [
        "VM",
        "KVM",
        "XEN",
        "AWS",
        "AZURE",
        "GCP",
        "HV",
    ]

    is_vm = False

    for word in vm_words:
        if word in all_text:
            is_vm = True
            break

    is_faz = (
        "FORTIANALYZER" in all_text
        or "FAZ" in all_text
    )

    return platform_type, platform_full, is_faz, is_vm


def is_cloud_platform(platform):
    platform = platform.upper()

    return "CLOUD" in platform


def is_fmg_cloud_platform(platform):
    platform = platform.upper()

    return (
        is_cloud_platform(platform)
        and (
            "FMG" in platform
            or "FORTIMANAGER" in platform
        )
    )


def is_faz_cloud_platform(platform):
    platform = platform.upper()

    return (
        is_cloud_platform(platform)
        and (
            "FAZ" in platform
            or "FORTIANALYZER" in platform
        )
    )


# ================
# GET VM RESOURCES
# ================

def get_resources(text):
    cpu_section = get_section(
        text,
        "### diag system print cpuinfo"
    )

    cpu_list = re.findall(
        r"^processor\s*:\s*(\d+)",
        cpu_section,
        re.MULTILINE
    )

    if cpu_list:
        cpu = max(map(int, cpu_list)) + 1
    else:
        cpu = 0

    mem_section = get_section(
        text,
        "### Memory info"
    )

    mem_total = find_value(
        r"MemTotal:\s+(\d+)\s*kB",
        mem_section
    )

    if mem_total:
        ram = kb_to_gb(mem_total)
    else:
        ram = 0

    disk_match = re.search(
        r"Hard Disk:\s*\n\s*Total:\s+([\d,]+)\s*KB",
        text
    )

    if disk_match:
        disk = kb_to_gb(disk_match.group(1))
    else:
        disk = 0

    return cpu, ram, disk


# =================
# VM RESOURCE CHECK
# =================

def check_vm_resources(
    cpu,
    ram,
    disk,
    req_cpu,
    req_ram,
    recommend_ram=True
):
    healthy = True

    blank()
    info(f"Detected CPU  : {cpu}")
    info(f"Detected RAM  : {ram:.1f} GB")
    info(f"Detected Disk : {disk:.1f} GB")
    blank()

    if cpu < req_cpu:
        crit(f"CPU below requirement ({cpu} < {req_cpu})")
        recommend(f"Increase VM CPU allocation to at least {req_cpu} vCPU")
        healthy = False
    else:
        ok(f"CPU meets requirement ({req_cpu})")

    if ram < req_ram:
        if within_tolerance(ram, req_ram):
            ok(
                f"RAM within {VM_RESOURCE_TOLERANCE_PERCENT}% "
                f"tolerance ({ram:.1f} GB, required {req_ram} GB)"
            )
        else:
            crit(f"RAM below requirement ({ram:.1f} < {req_ram} GB)")

            if recommend_ram:
                recommend(f"Increase VM RAM allocation to at least {req_ram} GB")

            healthy = False
    else:
        ok(f"RAM meets requirement ({ram:.1f} GB)")

    if disk < DISK_REQUIREMENT_GB:
        if within_tolerance(disk, DISK_REQUIREMENT_GB):
            ok(
                f"Disk within {VM_RESOURCE_TOLERANCE_PERCENT}% "
                f"tolerance ({disk:.1f} GB, required {DISK_REQUIREMENT_GB} GB)"
            )
        else:
            crit(
                f"Disk below requirement "
                f"({disk:.1f} < {DISK_REQUIREMENT_GB} GB)"
            )
            recommend(
                f"Increase VM disk size to at least "
                f"{DISK_REQUIREMENT_GB} GB"
            )
            healthy = False
    else:
        ok(f"Disk meets requirement ({disk:.1f} GB)")

    return healthy


# ==============
# SYSTEM STATUS
# ==============

def check_system_status(text):
    section("SYSTEM STATUS")

    status = get_section(
        text,
        "### get system status"
    )

    fields = [
        "Platform Full Name",
        "Platform Type",
        "Version",
        "Serial Number",
        "Hostname",
        "HA Mode",
        "License Status",
        "Admin Domain Configuration",
        "Max Number of Admin Domains",
        "FIPS Mode",
    ]

    for field in fields:
        value = find_value(
            rf"^{re.escape(field)}\s*:\s*(.+)$",
            status
        )

        if value:
            info(f"{field:<32}: {value}")


# ==========
# FMG SIZING
# ==========

def check_fmg(text, is_vm, platform_check):
    section("FMG SIZING")

    dvm = get_section(
        text,
        "### diag dvm device list"
    )

    managed = find_value(
        r"There are currently (\d+) devices/vdoms managed",
        dvm
    )

    devices = int(managed) if managed else 0

    info(f"Managed Devices : {devices}")
    blank()

    tier = get_required_tier(
        devices,
        FMG_SIZING
    )

    max_devices = tier[0]
    req_ram = tier[1]
    req_cpu = tier[2]

    info(
        f"Required Tier : "
        f"{req_cpu} CPU / "
        f"{req_ram} GB RAM / "
        f"{DISK_REQUIREMENT_GB} GB Disk"
    )
    info(f"Reference: {FMG_MIN_RESOURCE_URL}")

    usage = (devices / max_devices) * 100

    if usage >= 80:
        crit(f"Tier utilization high ({usage:.1f}%)")
    elif usage >= 60:
        warn(f"Tier utilization moderate ({usage:.1f}%)")
    else:
        ok(f"Tier utilization healthy ({usage:.1f}%)")

    info(
        f"Tier utilization is based on managed devices "
        f"({devices}) divided by the selected tier capacity "
        f"({max_devices})"
    )

    blank()

    if is_fmg_cloud_platform(platform_check):
        info("FortiManager Cloud platform detected")
        info(
            "VM CPU / RAM / Disk validation skipped because "
            "resources are managed by FortiManager Cloud"
        )

        return True, devices, req_ram

    if not is_vm:
        info("Hardware appliance detected")
        info("Check hardware datasheet:")
        info("https://docs.fortinet.com/product/fortimanager/hardware")

        return True, devices, req_ram

    cpu, ram, disk = get_resources(text)

    healthy = check_vm_resources(
        cpu,
        ram,
        disk,
        req_cpu,
        req_ram,
        recommend_ram=False
    )

    return healthy, devices, req_ram


# =========
# FDS CHECK
# =========

# FortiGuard preload database sizes (GB) as of Jan 2026
# https://docs.fortinet.com/document/fortimanager/8.0.0/best-practices/14860/fortimanager-performance-and-sizing-in-closed-networks

FDS_DATABASES = {
    "wf": 13,
    "iot": 18,
    "fq": 5,
    "as": 0.5,
    "av": 0.5,
}


def check_fds(text, devices, req_ram):
    section("FDS SIZING")

    # Runtime FortiGuard services
    fgd_section = get_section(
        text,
        "### diag fmupdate view-service-info fgd"
    )

    fds_section = get_section(
        text,
        "### diag fmupdate view-service-info fds"
    )

    service_section = (
        fgd_section + "\n" + fds_section
    )

    if not service_section.strip():
        info("FDS service info not found")

        cpu, ram, disk = get_resources(text)

        if (
            ram < req_ram
            and not within_tolerance(ram, req_ram)
        ):
            recommend(f"Increase VM RAM allocation to at least {req_ram} GB")

        return True

    enabled_services = []

    for line in service_section.splitlines():
        line = line.strip()

        match = re.search(
            r"^(.*?):\s*on$",
            line,
            re.IGNORECASE
        )

        if match:
            service = match.group(1).strip()

            # Avoid duplicates
            if service not in enabled_services:
                enabled_services.append(service)

    # No active services
    if not enabled_services:
        ok("No active FortiGuard services detected")
        return True

    # Runtime status
    info("FMG has active FortiGuard services")

    for service in enabled_services:
        ok(f"{service} : on")

    blank()

    # Parse preload settings
    fgd_config = get_config_block(
        text,
        "config fmupdate fgd-setting"
    )

    preload_names = [
        "wf",
        "iot",
        "fq",
        "as",
        "av",
    ]

    preload_state = {}

    for preload in preload_names:
        enable_pattern = (
            rf"set\s+{preload}-preload\s+enable"
        )

        disable_pattern = (
            rf"set\s+{preload}-preload\s+disable"
        )

        if re.search(enable_pattern, fgd_config):
            preload_state[preload] = "enabled"
        elif re.search(disable_pattern, fgd_config):
            preload_state[preload] = "disabled"
        else:
            preload_state[preload] = "default"

    # Display preload state
    info("Preload Configuration")
    info(
        "WF=WebFilter  "
        "IOT=IoT  "
        "FQ=File Query  "
        "AS=Antispam  "
        "AV=Antivirus"
    )
    blank()

    for preload, state in preload_state.items():
        if state == "enabled":
            info(f"{preload.upper():<6}: ENABLED")
        else:
            info(f"{preload.upper():<6}: disabled")

    blank()

    # Determine enabled preload databases
    enabled_preloads = []

    for preload, state in preload_state.items():
        if state == "enabled":
            enabled_preloads.append(preload)

    # No explicit preload warning
    if not enabled_preloads:
        warn("No explicit preload services enabled")
        warn(
            "Disabled preload reduces RAM usage "
            "but increases disk I/O wait and CPU usage"
        )
        blank()

    # Official Fortinet RAM formula
    # VMtotal GB = FMGreq + 2 × (WFdb + IOTdb + FQdb + ASdb + AVQdb)
    preload_total = 0

    for preload in enabled_preloads:
        preload_total += FDS_DATABASES.get(preload, 0)

    additional_ram = (2 * preload_total)
    required_ram = (req_ram + additional_ram)

    info(f"Base FMG RAM Requirement : {req_ram} GB")
    info(f"Additional FDS RAM : {additional_ram:.1f} GB")
    info(f"Total Recommended RAM : {required_ram:.1f} GB")

    blank()

    # Validate actual RAM
    cpu, ram, disk = get_resources(text)

    info(f"Detected RAM : {ram:.1f} GB")

    healthy = True

    if ram < required_ram:
        if within_tolerance(ram, required_ram):
            ok(
                f"RAM within {VM_RESOURCE_TOLERANCE_PERCENT}% tolerance "
                f"for Fortinet recommended FDS sizing "
                f"({ram:.1f} GB, recommended {required_ram:.1f} GB)"
            )
        else:
            crit("RAM below Fortinet recommended FDS sizing")

            # FDS RAM recommendation already includes base FMG RAM.
            # Remove lower base RAM recommendation to avoid duplicate guidance.
            remove_recommendation(r"Increase VM RAM allocation")

            recommend(
                "Increase VM RAM to meet "
                f"recommended sizing ({required_ram:.1f} GB)"
            )

            healthy = False
    else:
        ok("RAM meets Fortinet recommended FDS sizing")

    blank()

    # WebFilter recommendation
    wf_state = preload_state.get("wf")

    if (
        ram >= 60
        and wf_state == "disabled"
    ):
        warn("WebFilter preload disabled on high-memory deployment")
        recommend("Enable WebFilter preload for high-memory deployments")

    # Parse max-work
    fds_config = get_config_block(
        text,
        "config fmupdate fds-setting"
    )

    max_work = find_value(
        r"set\s+max-work\s+(\d+)",
        fds_config
    )

    # Default FMG value is 1
    if max_work:
        max_work = int(max_work)
        info(f"Configured max-work : {max_work}")
    else:
        max_work = 1
        info("Configured max-work : default (1)")

    # Fortinet recommendations
    if devices <= 50:
        recommended = 1
        recommendation_reason = "small deployment"
    elif devices <= 1000:
        recommended = 10
        recommendation_reason = "medium deployment"
    else:
        recommended = 24
        recommendation_reason = "large deployment"

    info(
        f"Recommended max-work : "
        f"{recommended} "
        f"({recommendation_reason})"
    )

    blank()

    if max_work < recommended:
        warn("Configured max-work below recommended value")
        recommend(
            f"Increase max-work to {recommended}\n\n"
            "Recommended CLI:\n"
            "config fmupdate fds-setting\n"
            f"set max-work {recommended}\n"
            "end\n\n"
            "Reference:\n"
            f"{FDS_SIZING_URL}"
        )
    else:
        ok("max-work setting looks good")

    # Platform limitations
    status = get_section(
        text,
        "### get system status"
    )

    platform = find_value(
        r"Platform Type\s*:\s*(.+)",
        status
    ) or ""

    if (
        "FMG-300E" in platform
        and enabled_preloads
    ):
        warn("FMG-300E may be insufficient for heavy preload workloads")
        recommend("Consider larger FMG platform for heavy preload workloads")

    return healthy


# ===========
# FAZ SIZING
# ===========

def check_faz_cloud(text, platform_check):
    section("FAZ CLOUD SIZING")

    info("FortiAnalyzer Cloud platform detected")
    info(
        "VM CPU / RAM / Disk validation skipped because "
        "resources are managed by FortiAnalyzer Cloud"
    )
    info(
        "Use FortiAnalyzer Cloud service quota, storage usage, "
        "and licensed log rate instead of VM hardware sizing"
    )

    limits = get_section(
        text,
        "### get system loglimits"
    )

    gbday = find_value(
        r"GB/day\s*:\s*(.+)",
        limits
    )

    peak_raw = find_value(
        r"Peak Log Rate\s*:\s*(.+)",
        limits
    )

    sustained = find_value(
        r"Sustained Log Rate\s*:\s*(.+)",
        limits
    )

    if gbday:
        info(f"Licensed GB/day         : {gbday}")

    if peak_raw:
        info(f"Licensed Peak Rate      : {peak_raw}")

    if sustained:
        info(f"Licensed Sustained Rate : {sustained}")

    info(f"Reference: {FAZ_CLOUD_LIMITATION_URL}")

    return True


def check_faz(text, is_vm):
    section("FAZ SIZING")

    limits = get_section(
        text,
        "### get system loglimits"
    )

    gbday = find_value(
        r"GB/day\s*:\s*(.+)",
        limits
    ) or "Unknown"

    peak_raw = find_value(
        r"Peak Log Rate\s*:\s*(.+)",
        limits
    )

    sustained = find_value(
        r"Sustained Log Rate\s*:\s*(.+)",
        limits
    ) or "Unknown"

    if peak_raw:
        if peak_raw.lower() == "unlimited":
            peak = None
            peak_display = "Unlimited"
        else:
            peak = int(
                re.sub(r"[^\d]", "", peak_raw)
            )
            peak_display = str(peak)
    else:
        peak = 0
        peak_display = "Unknown"

    info(f"Licensed GB/day         : {gbday}")
    info(f"Licensed Peak Rate      : {peak_display}")
    info(f"Licensed Sustained Rate : {sustained}")
    blank()

    lograte = get_any_section(
        text,
        [
            "### diag fortilogd lograte",
            "### diagnose fortilogd lograte",
        ]
    )

    actual_rate = None

    patterns = [
        r"last 60 seconds:\s*([\d.]+)",
        r"last 30 seconds:\s*([\d.]+)",
        r"last 5 seconds:\s*([\d.]+)",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            lograte,
            re.IGNORECASE
        )

        if match:
            actual_rate = float(match.group(1))
            break

    if actual_rate is None:
        warn("Could not determine actual log rate")
        return False

    config = get_config_block(
        text,
        "config system log-forward"
    )

    forwarders = re.findall(
        r'set\s+server-name\s+"([^"]+)"',
        config
    )

    forwarder_count = len(forwarders)
    effective_rate = actual_rate * (1 + forwarder_count)

    info(f"Actual Log Rate       : {actual_rate:.0f}")
    info(f"Forwarders Configured : {forwarder_count}")

    if forwarder_count > 0:
        info(
            f"Effective Formula : "
            f"{actual_rate:.0f} x (1 + {forwarder_count})"
        )
        info(f"Effective Rate    : {effective_rate:.0f} logs/sec")
    else:
        info(f"Effective Rate : {effective_rate:.0f} logs/sec")

    tier = get_required_tier(
        effective_rate,
        FAZ_SIZING
    )

    req_rate = tier[0]
    req_ram = tier[1]
    req_cpu = tier[2]
    req_iops = tier[3]

    info(f"Required Tier : {req_cpu} CPU / {req_ram} GB RAM")
    info(f"Reference: {FAZ_MIN_RESOURCE_URL}")

    healthy = True

    if is_vm:
        cpu, ram, disk = get_resources(text)

        healthy = check_vm_resources(
            cpu,
            ram,
            disk,
            req_cpu,
            req_ram,
            recommend_ram=True
        )

        info(f"Required IOPS : {req_iops}")
        warn(
            f"Verify hypervisor/storage can provide "
            f"{req_iops} IOPS"
        )
    else:
        info("Hardware appliance detected")
        info("Check hardware datasheet:")
        info("https://docs.fortinet.com/product/fortianalyzer/hardware")

    if peak is None:
        ok("Unlimited peak license detected")
    elif peak == 0:
        warn("Licensed peak rate unavailable")
    elif actual_rate > peak:
        crit("Actual log rate exceeds license")
        healthy = False
    elif actual_rate > peak * 0.8:
        warn("Actual log rate nearing license limit")
    else:
        ok("Actual log rate within license")

    return healthy


# ====================
# FINAL RESULT / TL;DR
# ====================

def final_result(product, healthy):
    section("FINAL RESULT")

    # Overall status
    if healthy:
        ok(f"{product} sizing looks GOOD")
    else:
        crit(f"{product} sizing is NOT sufficient")

    # Recommendations
    if RECOMMENDATIONS:
        blank()
        warn("Recommendations:")

        for index, item in enumerate(RECOMMENDATIONS, start=1):
            warn(f"{index}. {item}")


# =====
# MAIN
# =====

def run(path, save_combined=None):
    RECOMMENDATIONS.clear()

    text, display_name = load_input_file(
        path,
        save_combined=save_combined
    )

    platform, platform_full, is_faz, is_vm = detect_product(text)
    platform_check = f"{platform} {platform_full}"

    product = (
        "FortiAnalyzer"
        if is_faz
        else "FortiManager"
    )

    section(f"{product} TAC Sizing Tool")
    info(f"File     : {display_name}")
    info(f"Platform : {platform}")

    if is_fmg_cloud_platform(platform_check):
        info("Deployment : FortiManager Cloud")
    elif is_faz_cloud_platform(platform_check):
        info("Deployment : FortiAnalyzer Cloud")
    else:
        info(f"VM       : {is_vm}")

    check_system_status(text)

    # FAZ
    if is_faz:
        if is_faz_cloud_platform(platform_check):
            healthy = check_faz_cloud(
                text,
                platform_check
            )
        else:
            healthy = check_faz(text, is_vm)

    # FMG
    else:
        healthy, devices, req_ram = check_fmg(
            text,
            is_vm,
            platform_check
        )

        if is_fmg_cloud_platform(platform_check):
            section("FORTIGUARD / FDS CHECK")
            info("FortiManager Cloud platform detected")
            info(
                "FDS sizing check skipped because FortiManager Cloud "
                "does not provide the FortiGuard update service"
            )
            info(f"Reference: {FMG_CLOUD_LIMITATION_URL}")
        else:
            fds_healthy = check_fds(text, devices, req_ram)

            # Combine FMG + FDS health
            healthy = (healthy and fds_healthy)

    # Final TL;DR
    final_result(product, healthy)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Analyze FortiManager/FortiAnalyzer TAC report sizing. "
            "Supports txt/log TAC reports and GUI-downloaded tar.gz/zip TAC archives."
        )
    )

    parser.add_argument(
        "file",
        help="TAC report file: .txt, .log, .tar, .tar.gz, .tgz, .gz, or .zip"
    )

    parser.add_argument(
        "--save-combined",
        help="Optional path to save the combined TAC report when input is an archive"
    )

    args = parser.parse_args()

    run(
        args.file,
        save_combined=args.save_combined
    )