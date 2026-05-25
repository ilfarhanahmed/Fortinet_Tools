#!/usr/bin/env python3

"""
FortiManager / FortiAnalyzer TAC Sizing Tool
Author: Farhan Ahmed - ETAC-AMER

This tool analyzes FortiManager (FMG) and FortiAnalyzer (FAZ)
TAC reports and validates system sizing based on Fortinet
recommended deployment guidelines.

Checks Performed
--------------------

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
--------------------

FMG:
https://docs.fortinet.com/document/fortimanager-private-cloud/8.0.0/kvm-administration-guide/583600/minimum-system-requirements

FAZ:
https://docs.fortinet.com/document/fortianalyzer-private-cloud/8.0.0/kvm-administration-guide/583600/minimum-system-requirements

Hardware Datasheets:
https://docs.fortinet.com/product/fortimanager/hardware
https://docs.fortinet.com/product/fortianalyzer/hardware
"""

import re
import sys
from pathlib import Path


# ==============
# PRINT HELPERS
# ==============

def section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def ok(msg):
    print(f"[OK] {msg}")


def warn(msg):
    print(f"[WARN] {msg}")


def crit(msg):
    print(f"[CRIT] {msg}")


def info(msg):
    print(f"[INFO] {msg}")


# ==============
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


# =============
# FILE HELPERS
# ============

def load_file(path):
    try:
        text = Path(path).read_text(errors="replace")
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)
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


# ==================
# PRODUCT DETECTION
# =================

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

    is_faz = "FORTIANALYZER" in all_text

    return platform_type, is_faz, is_vm


# ================
# GET VM RESOURCES
# =================

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


# ===================
# VM RESOURCE CHECK
# ===================

def check_vm_resources(cpu, ram, disk, req_cpu, req_ram):
    healthy = True

    print()

    info(f"Detected CPU  : {cpu}")
    info(f"Detected RAM  : {ram:.1f} GB")
    info(f"Detected Disk : {disk:.1f} GB")

    print()

    if cpu < req_cpu:
        crit(f"CPU below requirement ({cpu} < {req_cpu})")
        healthy = False
    else:
        ok(f"CPU meets requirement ({req_cpu})")

    if ram < req_ram:
        crit(f"RAM below requirement ({ram:.1f} < {req_ram} GB)")
        healthy = False
    else:
        ok(f"RAM meets requirement ({req_ram} GB)")

    if disk < 500:
        crit(f"Disk below requirement ({disk:.1f} < 500 GB)")
        healthy = False
    else:
        ok("Disk meets requirement (500 GB)")

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
            print(f"{field:<32}: {value}")


# ==========
# FMG SIZING
# ==========

def check_fmg(text, is_vm):
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

    tier = get_required_tier(
        devices,
        FMG_SIZING
    )

    max_devices = tier[0]
    req_ram = tier[1]
    req_cpu = tier[2]

    print()

    info(
        f"Required Tier : "
        f"{req_cpu} CPU / "
        f"{req_ram} GB RAM / "
        f"500 GB Disk"
    )

    usage = (devices / max_devices) * 100

    if usage >= 80:
        crit(f"Tier utilization high ({usage:.1f}%)")

    elif usage >= 60:
        warn(f"Tier utilization moderate ({usage:.1f}%)")

    else:
        ok(f"Tier utilization healthy ({usage:.1f}%)")

    if not is_vm:
        print()
        info("Hardware appliance detected")
        info("Check hardware datasheet:")
        info("https://docs.fortinet.com/product/fortimanager/hardware")

        return True

    cpu, ram, disk = get_resources(text)

    healthy = check_vm_resources(
        cpu,
        ram,
        disk,
        req_cpu,
        req_ram
    )

    return healthy, devices, req_ram


# =========
# FDS CHECK
# =========

# FortiGuard preload database sizes (GB) as of Jan 2026
# Refer: https://docs.fortinet.com/document/fortimanager/8.0.0/best-practices/14860/fortimanager-performance-and-sizing-in-closed-networks

FDS_DATABASES = {
    "wf": 13,
    "iot": 18,
    "fq": 5,
    "as": 0.5,
    "av": 0.5,
}

RECOMMENDATIONS = []


def recommend(msg):
    if msg not in RECOMMENDATIONS:
        RECOMMENDATIONS.append(msg)


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

    info(
        "FMG has active FortiGuard services"
    )

    print()

    for service in enabled_services:
        ok(f"{service} : on")

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

        if re.search(
                enable_pattern,
                fgd_config
        ):

            preload_state[preload] = "enabled"

        elif re.search(
                disable_pattern,
                fgd_config
        ):

            preload_state[preload] = "disabled"

        else:

            preload_state[preload] = "default"

    # Display preload state

    print()

    info("Preload Configuration")

    print(
        "WF=WebFilter  "
        "IOT=IoT  "
        "FQ=File Query  "
        "AS=Antispam  "
        "AV=Antivirus"
    )

    print()

    for preload, state in preload_state.items():

        if state == "enabled":

            print(
                f"{preload.upper():<6}: ENABLED"
            )

        else:

            print(
                f"{preload.upper():<6}: disabled"
            )

    # Determine enabled preload databases

    enabled_preloads = []

    for preload, state in preload_state.items():

        if state == "enabled":
            enabled_preloads.append(preload)

    # No explicit preload warning

    if not enabled_preloads:
        print()

        warn(
            "No explicit preload services enabled"
        )

        warn(
            "Disabled preload reduces RAM usage "
            "but increases disk I/O wait and CPU usage"
        )

    # Official RAM formula
    # VMtotal GB = FMGreq + 2 × (WFdb + IOTdb + FQdb + ASdb + AVQdb)

    preload_total = 0

    for preload in enabled_preloads:
        preload_total += FDS_DATABASES.get(preload, 0)

    additional_ram = (2 * preload_total)

    required_ram = (req_ram + additional_ram)

    print()

    info(
        f"Base FMG RAM Requirement : "
        f"{req_ram} GB"
    )

    info(
        f"Additional FDS RAM : "
        f"{additional_ram:.1f} GB"
    )

    info(
        f"Total Recommended RAM : "
        f"{required_ram:.1f} GB"
    )

    # Validate actual RAM

    cpu, ram, disk = get_resources(text)

    print()

    info(f"Detected RAM : {ram:.1f} GB")

    healthy = True

    if ram < required_ram:

        crit(
            "RAM below Fortinet recommended "
            "FDS sizing"
        )

        recommend(
            "Increase VM RAM to meet "
            f"recommended sizing ({required_ram:.1f} GB)"
        )

        healthy = False

    else:

        ok(
            "RAM meets Fortinet recommended "
            "FDS sizing"
        )

    # WebFilter recommendation

    wf_state = preload_state.get("wf")

    if (
            ram >= 60
            and wf_state == "disabled"
    ):
        print()

        warn(
            "WebFilter preload disabled on "
            "high-memory deployment"
        )
        recommend(
            "Enable WebFilter preload "
            "for high-memory deployments"
        )

    # Parse max-work

    fds_config = get_config_block(
        text,
        "config fmupdate fds-setting"
    )

    max_work = find_value(
        r"set\s+max-work\s+(\d+)",
        fds_config
    )

    print()

    # Default FMG value is 1

    if max_work:

        max_work = int(max_work)

        info(
            f"Configured max-work : "
            f"{max_work}"
        )

    else:

        max_work = 1

        info(
            "Configured max-work : "
            "default (1)"
        )

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

    if max_work < recommended:

        warn(
            "Configured max-work below "
            "recommended value"
        )

        recommend(
            f"Increase max-work to "
            f"{recommended}"
        )

    else:

        ok(
            "max-work setting looks good"
        )

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
        print()

        warn(
            "FMG-300E may be insufficient "
            "for heavy preload workloads"
        )
        recommend(
            "Consider larger FMG platform "
            "for heavy preload workloads"
        )

    return healthy


# =========
# FAZ SIZING
# =========

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

    print()

    lograte = get_section(
        text,
        "### diag fortilogd lograte"
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

    print()

    if forwarder_count > 0:

        info(
            f"Effective Formula : "
            f"{actual_rate:.0f} x (1 + {forwarder_count})"
        )

        info(
            f"Effective Rate    : "
            f"{effective_rate:.0f} logs/sec"
        )

    else:

        info(
            f"Effective Rate : "
            f"{effective_rate:.0f} logs/sec"
        )

    print()

    tier = get_required_tier(
        effective_rate,
        FAZ_SIZING
    )

    req_rate = tier[0]
    req_ram = tier[1]
    req_cpu = tier[2]
    req_iops = tier[3]

    info(
        f"Required Tier : "
        f"{req_cpu} CPU / "
        f"{req_ram} GB RAM"
    )

    healthy = True

    if is_vm:

        cpu, ram, disk = get_resources(text)

        healthy = check_vm_resources(
            cpu,
            ram,
            disk,
            req_cpu,
            req_ram
        )

        print()

        info(f"Required IOPS : {req_iops}")

        warn(
            f"Verify hypervisor/storage can provide "
            f"{req_iops} IOPS"
        )

    else:

        print()
        info("Hardware appliance detected")
        info("Check hardware datasheet:")
        info("https://docs.fortinet.com/product/fortianalyzer/hardware")

    print()

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


# =============
# FINAL RESULT / TL;DR
# =============

def final_result(product, healthy):
    section("FINAL RESULT")

    # Overall status

    if healthy:

        ok(f"{product} sizing looks GOOD")

    else:

        crit(
            f"{product} sizing is NOT sufficient"
        )

    # Recommendations

    if RECOMMENDATIONS:

        print()

        for index, item in enumerate(
                RECOMMENDATIONS,
                start=1
        ):
            print(
                f"{index}. {item}"
            )


# =====
# MAIN
# =====

def main():
    if len(sys.argv) < 2:
        print(
            f"Usage: python3 {sys.argv[0]} <tac_report>"
        )

        sys.exit(1)

    file_path = sys.argv[1]

    text = load_file(file_path)

    platform, is_faz, is_vm = detect_product(text)

    product = (
        "FortiAnalyzer"
        if is_faz
        else "FortiManager"
    )

    print()
    print("=" * 50)
    print(f"{product} TAC Sizing Tool")
    print("=" * 50)

    print(f"File     : {Path(file_path).name}")
    print(f"Platform : {platform}")
    print(f"VM       : {is_vm}")

    check_system_status(text)

    # FAZ
    if is_faz:
        healthy = check_faz(text,is_vm)

    # FMG
    else:
        healthy, devices, req_ram = check_fmg(text,is_vm)
        fds_healthy = check_fds(text,devices,req_ram)
        # Combine FMG + FDS health
        healthy = (healthy and fds_healthy)

    # Final TL;DR
    final_result(product,healthy)

    print()

if __name__ == "__main__":
    main()
