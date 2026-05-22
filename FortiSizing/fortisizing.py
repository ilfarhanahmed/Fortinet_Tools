#!/usr/bin/env python3

"""
FortiManager / FortiAnalyzer TAC Sizing Tool
Simple TAC sizing checker

Author: Farhan Ahmed - ETAC-AMER
"""

import re
import sys
from pathlib import Path


# =========================================================
# PRINT HELPERS
# =========================================================

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


# =========================================================
# SIZING TABLES
# =========================================================

# FMG sizing
# devices, RAM GB, CPU
FMG_SIZING = [
    (100, 16, 4),
    (300, 16, 6),
    (1200, 32, 6),
    (4000, 64, 16),
    (10000, 128, 24),
]

# FAZ sizing
# logs/sec, RAM GB, CPU, IOPS
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


# =========================================================
# BASIC HELPERS
# =========================================================

def load_file(path):

    try:
        text = Path(path).read_text(errors="replace")

        # remove ansi colors
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)

        return text

    except FileNotFoundError:
        crit(f"File not found: {path}")
        sys.exit(1)


def get_section(text, start_text):

    start = text.find(start_text)

    if start == -1:
        return ""

    start = start + len(start_text)

    end = text.find("### ", start)

    if end == -1:
        return text[start:]

    return text[start:end]


def get_config_block(text, start_text):

    start = text.find(start_text)

    if start == -1:
        return ""

    end = text.find("\nend\n", start)

    if end == -1:
        return text[start:]

    return text[start:end]


def find_value(pattern, text):

    match = re.search(pattern, text, re.MULTILINE)

    if match:
        return match.group(1).strip()

    return None


def kb_to_gb(kb):

    kb = kb.replace(",", "")

    return float(kb) / 1024 / 1024


# =========================================================
# GET VM RESOURCES
# =========================================================

def get_resources(text):

    # CPU
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

    # RAM
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

    # DISK
    disk_match = re.search(
        r"Hard Disk:\s*\n\s*Total:\s+([\d,]+)\s*KB",
        text
    )

    if disk_match:
        disk = kb_to_gb(disk_match.group(1))
    else:
        disk = 0

    return cpu, ram, disk


# =========================================================
# GET REQUIRED TIER
# =========================================================

def get_required_tier(value, table):

    for row in table:

        if value <= row[0]:
            return row

    return table[-1]


# =========================================================
# SYSTEM STATUS
# =========================================================

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


# =========================================================
# VM RESOURCE CHECK
# =========================================================

def check_vm_resources(cpu, ram, disk, req_cpu, req_ram):

    healthy = True

    print()

    info(f"Detected CPU  : {cpu}")
    info(f"Detected RAM  : {ram:.1f} GB")
    info(f"Detected Disk : {disk:.1f} GB")

    print()

    # CPU
    if cpu < req_cpu:
        crit(f"CPU below requirement ({cpu} < {req_cpu})")
        healthy = False
    else:
        ok(f"CPU meets requirement ({req_cpu})")

    # RAM
    if ram < req_ram:
        crit(f"RAM below requirement ({ram:.1f} < {req_ram} GB)")
        healthy = False
    else:
        ok(f"RAM meets requirement ({req_ram} GB)")

    # DISK
    if disk < 500:
        crit(f"Disk below requirement ({disk:.1f} < 500 GB)")
        healthy = False
    else:
        ok("Disk meets requirement (500 GB)")

    return healthy


# =========================================================
# FINAL RESULT
# =========================================================

def final_result(product, healthy):

    section(f"{product} RESULT")

    if healthy:
        ok(f"{product} sizing looks GOOD")
    else:
        crit(f"{product} sizing is NOT sufficient")


# =========================================================
# FMG CHECK
# =========================================================

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

    if managed:
        devices = int(managed)
    else:
        devices = 0

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

    # hardware
    if not is_vm:

        print()
        info("Hardware appliance detected")
        final_result("FMG", True)
        return

    # vm checks
    cpu, ram, disk = get_resources(text)

    healthy = check_vm_resources(
        cpu,
        ram,
        disk,
        req_cpu,
        req_ram
    )

    final_result("FMG", healthy)


# =========================================================
# FAZ CHECK
# =========================================================

def check_faz(text, is_vm):

    section("FAZ SIZING")

    # license info
    limits = get_section(
        text,
        "### get system loglimits"
    )

    gbday_raw = find_value(
        r"GB/day\s*:\s*(.+)",
        limits
    )

    peak_raw = find_value(
        r"Peak Log Rate\s*:\s*(.+)",
        limits
    )

    sustained_raw = find_value(
        r"Sustained Log Rate\s*:\s*(.+)",
        limits
    )

    # GB/day
    if gbday_raw:

        if gbday_raw.lower() == "unlimited":
            gbday = "Unlimited"
        else:
            gbday = gbday_raw

    else:
        gbday = "Unknown"

    # Peak
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

    # Sustained
    if sustained_raw:

        if sustained_raw.lower() == "unlimited":
            sustained = "Unlimited"
        else:
            sustained = sustained_raw

    else:
        sustained = "Unknown"

    info(f"Licensed GB/day         : {gbday}")
    info(f"Licensed Peak Rate      : {peak_display}")
    info(f"Licensed Sustained Rate : {sustained}")

    print()

    # actual log rate
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
        return

    # forwarders
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

    # required sizing tier
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

    # VM checks
    if is_vm:

        cpu, ram, disk = get_resources(text)

        healthy = check_vm_resources(
            cpu,
            ram,
            disk,
            req_cpu,
            req_ram
        )

    else:

        print()
        info("Hardware appliance detected")

    print()

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
        print()
    else:

        info(
            f"Effective Rate : "
            f"{effective_rate:.0f} logs/sec"
        )

    # iops
    if is_vm:

        print()

        info(f"Required IOPS : {req_iops}")

        warn(
            "Verify hypervisor/storage can provide "
            f"{req_iops} IOPS"
        )

    print()

    # license validation
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

    final_result("FAZ", healthy)


# =========================================================
# PRODUCT DETECTION
# =========================================================

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


# =========================================================
# MAIN
# =========================================================

def main():

    if len(sys.argv) < 2:

        print(f"Usage: python3 {sys.argv[0]} <tac_report>")
        sys.exit(1)

    file_path = sys.argv[1]

    text = load_file(file_path)

    platform, is_faz, is_vm = detect_product(text)

    if is_faz:
        product = "FortiAnalyzer"
    else:
        product = "FortiManager"

    print()
    print("=" * 70)
    print(f"{product} TAC Sizing Tool")
    print("=" * 70)

    print(f"File     : {Path(file_path).name}")
    print(f"Platform : {platform}")
    print(f"VM       : {is_vm}")

    check_system_status(text)

    if is_faz:
        check_faz(text, is_vm)
    else:
        check_fmg(text, is_vm)

    print()


if __name__ == "__main__":
    main()