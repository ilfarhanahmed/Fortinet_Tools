
#!/usr/bin/env python3

"""
FortiManager-FortiAnalyzer System Performance Monitor
Author: Farhan Ahmed - www.farhan.ch
"""

import argparse
import configparser
import os
import re
import sys
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import urllib3


STATUS_API_PATH = "sys/status/"
FAZ_PERF_API_PATH = "/fazsys/monitor/system/performance/status"
CLI_PERF_API_PATH = "/cli/global/system/performance"
LOG_FORWARD_API_PATH = "/fazsys/monitor/logforward-status"
TOP_API_PATH = "/cli/global/exec/top"
IOTOP_API_PATH = "/cli/global/exec/iotop"

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def color(text, code, enabled=True):
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(text, enabled=True):
    return color(text, "31", enabled)


def yellow(text, enabled=True):
    return color(text, "33", enabled)


def green(text, enabled=True):
    return color(text, "32", enabled)


def cyan(text, enabled=True):
    return color(text, "36", enabled)


def bold(text, enabled=True):
    return color(text, "1", enabled)


def safe_float(value):
    try:
        return float(str(value).replace(",", "").replace("%", "").replace("KB", "").strip())
    except (TypeError, ValueError):
        return 0.0


def kb_to_gib(value):
    return safe_float(value) / 1024 / 1024


def percent(used, total):
    used = safe_float(used)
    total = safe_float(total)
    if total <= 0:
        return 0.0
    return used / total * 100


def health_label(value):
    value = safe_float(value)
    if value >= 90:
        return "CRITICAL"
    if value >= 80:
        return "WARNING"
    return "GOOD"


def health_color(text, value, enabled=True):
    value = safe_float(value)
    if value >= 90:
        return red(text, enabled)
    if value >= 80:
        return yellow(text, enabled)
    return green(text, enabled)


def make_bar(value, width=30, color_enabled=True):
    value = max(0, min(100, safe_float(value)))
    filled = int((value / 100) * width)
    empty = width - filled
    bar = "█" * filled + "░" * empty

    if value >= 90:
        return red(bar, color_enabled)
    if value >= 80:
        return yellow(bar, color_enabled)
    return green(bar, color_enabled)


def normalize_jsonrpc_url(url):
    url = url.strip().rstrip("/")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    if not url.endswith("/jsonrpc"):
        url += "/jsonrpc"

    return url


def mask_api_key(api_key):
    if not api_key:
        return "N/A"
    if len(api_key) <= 8:
        return "****"
    return api_key[:4] + "..." + api_key[-4:]


def parse_verify_ssl(value):
    value = str(value).strip()

    if value.lower() in ("true", "yes", "1", "on"):
        return True

    if value.lower() in ("false", "no", "0", "off"):
        return False

    if not os.path.exists(value):
        raise FileNotFoundError(f"SSL CA certificate file not found: {value}")

    return value


def load_config(config_file):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")

    config = configparser.ConfigParser()
    config.read(config_file)

    section_name = "config"

    if section_name not in config:
        raise ValueError(f"Missing [{section_name}] section in config file")

    device_config = config[section_name]

    url = device_config.get("url", "").strip()
    api_key = device_config.get("api_key", "").strip()
    verify_ssl = parse_verify_ssl(device_config.get("verify_ssl", fallback="false"))
    interval = device_config.getint("interval", fallback=5)

    if not url:
        raise ValueError(f"Missing 'url' under [{section_name}] in config file")

    if not api_key:
        raise ValueError(f"Missing 'api_key' under [{section_name}] in config file")

    return {
        "url": normalize_jsonrpc_url(url),
        "api_key": api_key,
        "verify_ssl": verify_ssl,
        "interval": interval
    }


def build_status_body():
    return {
        "method": "get",
        "params": [
            {
                "url": STATUS_API_PATH
            }
        ],
        "verbose": 1,
        "id": 1
    }


def build_faz_perf_body():
    return {
        "id": "3",
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "url": FAZ_PERF_API_PATH,
                "apiver": 3
            }
        ]
    }


def build_cli_perf_body():
    return {
        "id": "4",
        "method": "get",
        "params": [
            {
                "url": CLI_PERF_API_PATH
            }
        ]
    }

def build_top_body(top_n=50):
    return {
        "id": "6",
        "method": "exec",
        "params": [
            {
                "url": TOP_API_PATH,
                "data": {
                    "top-n": top_n,
                    "order-by": "cpu-usage"
                }
            }
        ]
    }


def build_iotop_body(top_n=50):
    return {
        "id": "7",
        "method": "exec",
        "params": [
            {
                "url": IOTOP_API_PATH,
                "data": {
                    "top-n": top_n
                }
            }
        ]
    }

def build_log_forward_body():
    return {
        "id": "5",
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "url": LOG_FORWARD_API_PATH,
                "apiver": 3
            }
        ]
    }


def extract_result(payload):
    result = payload.get("result")

    if isinstance(result, list):
        result = result[0] if result else None

    if not result:
        raise RuntimeError(f"Missing result in API response: {payload}")

    status = result.get("status")
    if isinstance(status, dict) and status.get("code") not in (0, None):
        raise RuntimeError(f"API error: {status}")

    if "data" not in result:
        raise RuntimeError(f"Missing result.data in API response: {payload}")

    return result


def fetch_api_data(url, api_key, body, verify_ssl, timeout):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    response = requests.post(
        url,
        headers=headers,
        json=body,
        verify=verify_ssl,
        timeout=timeout
    )

    response.raise_for_status()

    payload = response.json()
    result = extract_result(payload)

    return result.get("data")


def normalize_key(key):
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def find_value_by_key(obj, target_key):
    target = normalize_key(target_key)

    if isinstance(obj, dict):
        for key, value in obj.items():
            if normalize_key(key) == target:
                return value

        for value in obj.values():
            found = find_value_by_key(value, target_key)
            if found is not None:
                return found

    elif isinstance(obj, list):
        for item in obj:
            found = find_value_by_key(item, target_key)
            if found is not None:
                return found

    return None


def detect_platform(status_data):
    platform_type = find_value_by_key(status_data, "Platform Type")

    combined_text = f"{platform_type} {status_data}".lower()

    if "fortimanager" in combined_text or "fmg" in combined_text:
        return "FMG", str(platform_type or "Unknown")

    if "fortianalyzer" in combined_text or "faz" in combined_text:
        return "FAZ", str(platform_type or "Unknown")

    return "UNKNOWN", str(platform_type or "Unknown")


def parse_used_field(value):
    text = str(value or "")

    kb_match = re.search(r"([\d,]+)\s*KB", text, re.IGNORECASE)
    pct_match = re.search(r"([\d.]+)\s*%", text)

    return {
        "kb": safe_float(kb_match.group(1)) if kb_match else 0.0,
        "percent": safe_float(pct_match.group(1)) if pct_match else 0.0
    }


def parse_total_kb(value):
    return safe_float(value)


def parse_cli_performance(cli_data):
    cpu = cli_data.get("CPU", {})
    memory = cli_data.get("Memory", {})
    hard_disk = cli_data.get("Hard Disk", {})
    flash_disk = cli_data.get("Flash Disk", {})

    cpu_rows = []

    for key, value in cpu.items():
        match = re.match(r"CPU\[(\d+)\] usage", str(key))
        if not match:
            continue

        core_index = int(match.group(1))
        details = value.get("Details", {})
        used = safe_float(value.get("Usage"))

        cpu_rows.append({
            "label": f"CPU[{core_index}]",
            "used": used,
            "user": safe_float(details.get("%user")),
            "system": safe_float(details.get("%sys")),
            "nice": safe_float(details.get("%nice")),
            "idle": safe_float(details.get("%idle")),
            "iowait": safe_float(details.get("%iowait")),
            "irq": safe_float(details.get("%irq")),
            "softirq": safe_float(details.get("%softirq")),
            "source": "CLI"
        })

    cpu_rows.sort(key=lambda row: row["label"])

    mem_used = parse_used_field(memory.get("Used"))
    mem_total = parse_total_kb(memory.get("Total"))

    hard_used = parse_used_field(hard_disk.get("Used"))
    hard_total = parse_total_kb(hard_disk.get("Total"))

    flash_used = parse_used_field(flash_disk.get("Used"))
    flash_total = parse_total_kb(flash_disk.get("Total"))

    return {
        "cpu_used": safe_float(cpu.get("Used")),
        "cpu_used_ex_nice": safe_float(cpu.get("Used(Excluded NICE)")),
        "cpu_num": int(safe_float(cpu.get("CPU_num"))),
        "cpu_rows": cpu_rows,
        "memory": {
            "used_kb": mem_used["kb"],
            "total_kb": mem_total,
            "used_percent": mem_used["percent"]
        },
        "hard_disk": {
            "used_kb": hard_used["kb"],
            "total_kb": hard_total,
            "used_percent": hard_used["percent"],
            "iostat": hard_disk.get("IOStat", {})
        },
        "flash_disk": {
            "used_kb": flash_used["kb"],
            "total_kb": flash_total,
            "used_percent": flash_used["percent"],
            "iostat": flash_disk.get("IOStat", {})
        }
    }


def parse_faz_performance(faz_data):
    cpu = faz_data.get("cpu", {})
    mem = faz_data.get("mem", {})
    disk = faz_data.get("disk", {})
    receive_lograte = faz_data.get("receive-lograte", {})
    insert_lograte = faz_data.get("insert-lograte", {})

    cpu_rows = []

    for index, core in enumerate(cpu.get("cores", [])):
        idle = safe_float(core.get("idle"))
        used = 100 - idle

        cpu_rows.append({
            "label": f"CPU[{index}]",
            "used": used,
            "user": safe_float(core.get("user")),
            "system": safe_float(core.get("system")),
            "nice": safe_float(core.get("nice")),
            "idle": idle,
            "iowait": safe_float(core.get("iowait")),
            "irq": None,
            "softirq": None,
            "source": "FAZ Monitor"
        })

    hard_disk = disk.get("hard-disk", {})
    flash_disk = disk.get("flash-disk", {})

    return {
        "cpu_used": safe_float(cpu.get("used")),
        "cpu_used_ex_nice": safe_float(cpu.get("used-excluded-nice")),
        "cpu_num": len(cpu_rows),
        "cpu_rows": cpu_rows,
        "memory": {
            "used_kb": safe_float(mem.get("used")),
            "total_kb": safe_float(mem.get("total")),
            "used_percent": percent(mem.get("used"), mem.get("total"))
        },
        "hard_disk": {
            "used_kb": safe_float(hard_disk.get("used")),
            "total_kb": safe_float(hard_disk.get("total")),
            "used_percent": percent(hard_disk.get("used"), hard_disk.get("total")),
            "iostat": {
                "%util": hard_disk.get("iostat-util")
            }
        },
        "flash_disk": {
            "used_kb": safe_float(flash_disk.get("used")),
            "total_kb": safe_float(flash_disk.get("total")),
            "used_percent": percent(flash_disk.get("used"), flash_disk.get("total")),
            "iostat": {
                "%util": flash_disk.get("iostat-util")
            }
        },
        "receive_lograte": {
            "last_5": safe_float(receive_lograte.get("last-5sec")),
            "last_30": safe_float(receive_lograte.get("last-30sec")),
            "last_60": safe_float(receive_lograte.get("last-60sec"))
        },
        "insert_lograte": {
            "last_5": safe_float(insert_lograte.get("last-5sec")),
            "last_60": safe_float(insert_lograte.get("last-60sec"))
        }
    }


def parse_process_rate(value):
    """
    Converts values like:
    0.3
    0.3%
    0.00 K/s
    855.2m
    90.6m
    into numeric values where possible.
    """
    if value is None:
        return 0.0

    text = str(value).strip().lower()
    text = text.replace("%", "").replace("k/s", "").replace("kb/s", "").strip()

    multiplier = 1.0

    if text.endswith("g"):
        multiplier = 1024.0
        text = text[:-1]
    elif text.endswith("m"):
        multiplier = 1.0
        text = text[:-1]
    elif text.endswith("k"):
        multiplier = 1 / 1024
        text = text[:-1]

    try:
        return float(text.replace(",", "")) * multiplier
    except ValueError:
        return 0.0


def parse_top_processes(top_data, limit=10):
    """
    Parses /cli/global/exec/top response.
    Returns summary and top CPU processes.
    """
    if not isinstance(top_data, dict):
        return {}, []

    processes = top_data.get("lists", [])
    summary = top_data.get("summary", {})

    rows = []

    for item in processes:
        cpu_pct = safe_float(item.get("cpu_pct"))
        mem_pct = safe_float(item.get("mem_pct"))

        rows.append({
            "pid": item.get("pid", "N/A"),
            "cmd": item.get("cmd", "N/A"),
            "state": item.get("state", "N/A"),
            "cpu_pct": cpu_pct,
            "mem_pct": mem_pct,
            "res": item.get("res", "N/A"),
            "virt": item.get("virt", "N/A")
        })

    rows.sort(key=lambda row: row["cpu_pct"], reverse=True)

    return summary, rows[:limit]


def parse_iotop_processes(iotop_data, limit=10):
    """
    Parses /cli/global/exec/iotop response.
    Returns summary and top disk I/O processes.
    """
    if not isinstance(iotop_data, dict):
        return {}, []

    processes = iotop_data.get("lists", [])
    summary = iotop_data.get("summary", {})

    rows = []

    for item in processes:
        disk_read = parse_process_rate(item.get("disk_read"))
        disk_write = parse_process_rate(item.get("disk_write"))

        rows.append({
            "pid": item.get("pid", "N/A"),
            "cmd": item.get("cmd", "N/A"),
            "disk_read": disk_read,
            "disk_write": disk_write,
            "disk_read_text": item.get("disk_read", "0.00 K/s"),
            "disk_write_text": item.get("disk_write", "0.00 K/s"),
            "total_io": disk_read + disk_write
        })

    rows.sort(key=lambda row: row["total_io"], reverse=True)

    return summary, rows[:limit]

def run_refresh_calls(url, api_key, platform, verify_ssl, timeout, show_processes=False, top_n=50):
    tasks = {}

    max_workers = 5 if show_processes else 3

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks["cli_perf"] = executor.submit(
            fetch_api_data,
            url,
            api_key,
            build_cli_perf_body(),
            verify_ssl,
            timeout
        )

        if platform == "FAZ":
            tasks["faz_perf"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_faz_perf_body(),
                verify_ssl,
                timeout
            )

            tasks["log_forward"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_log_forward_body(),
                verify_ssl,
                timeout
            )

        if show_processes:
            tasks["top"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_top_body(top_n),
                verify_ssl,
                timeout
            )

            tasks["iotop"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_iotop_body(top_n),
                verify_ssl,
                timeout
            )

        results = {}
        errors = {}

        for name, future in tasks.items():
            try:
                results[name] = future.result()
            except Exception as e:
                errors[name] = str(e)

    return results, errors

def print_disk_io_row(name, disk_data):
    iostat = disk_data.get("iostat", {})

    print(
        f"{name:<12} "
        f"{kb_to_gib(disk_data.get('used_kb')):>10.2f} GiB "
        f"{kb_to_gib(disk_data.get('total_kb')):>10.2f} GiB "
        f"{disk_data.get('used_percent'):>8.2f}% "
        f"{safe_float(iostat.get('%util')):>8.2f}% "
        f"{safe_float(iostat.get('queue')):>8.2f} "
        f"{safe_float(iostat.get('r_kB/s')):>10.2f} "
        f"{safe_float(iostat.get('w_kB/s')):>10.2f} "
        f"{safe_float(iostat.get('tps')):>8.2f} "
        f"{safe_float(iostat.get('wait_ms')):>8.2f} "
        f"{safe_float(iostat.get('svc_ms')):>8.2f}"
    )


def print_log_forward_status(log_forward_data, color_enabled=True):
    print()
    print(bold("Log Forwarding Status", color_enabled))
    print("-" * 120)

    if not isinstance(log_forward_data, list):
        print(yellow("Log forwarding status unavailable or unexpected format.", color_enabled))
        return

    connected = 0
    disconnected = 0
    total_lograte = 0.0

    for item in log_forward_data:
        status = str(item.get("status", "unknown")).lower()
        lograte = safe_float(item.get("lograte"))

        total_lograte += lograte

        if status == "connected":
            connected += 1
        elif status == "disconnected":
            disconnected += 1

    visible_forwarders = connected + disconnected

    print(f"Visible Forwarders : {visible_forwarders}")
    print(f"Connected          : {green(str(connected), color_enabled)}")
    print(f"Disconnected       : {red(str(disconnected), color_enabled)}")
    print(f"Total Lograte      : {total_lograte:.4f} logs/sec")

    print()
    print(f"{'ID':<8} {'Status':<16} {'Lograte':>16}  Comment")
    print("-" * 120)

    for item in log_forward_data:
        forwarder_id = item.get("id", "N/A")
        status = str(item.get("status", "unknown")).lower()
        lograte = safe_float(item.get("lograte"))

        if status == "connected":
            status_text = green("connected", color_enabled)
            comment = "Forwarding logs" if lograte > 0 else "Connected, but current forwarding rate is 0"
        elif status == "disconnected":
            status_text = red("disconnected", color_enabled)
            comment = "Disconnected - check destination/connectivity"
        else:
            status_text = yellow(status, color_enabled)
            comment = "Unknown status returned by device"

        print(
            f"{str(forwarder_id):<8} "
            f"{status_text:<16} "
            f"{lograte:>12.4f} logs/sec  "
            f"{comment}"
        )


def print_process_details(top_summary, top_rows, iotop_summary, iotop_rows, color_enabled=True):
    print()
    print(bold("Top Processes - CPU", color_enabled))
    print("-" * 120)

    if top_summary:
        print(
            f"Load Avg 1m/5m/15m : "
            f"{top_summary.get('load_avg_1', 'N/A')} / "
            f"{top_summary.get('load_avg_5', 'N/A')} / "
            f"{top_summary.get('load_avg_15', 'N/A')}"
        )

        print(
            f"Memory             : "
            f"Used {top_summary.get('mem_used', 'N/A')} {top_summary.get('mem_unit', '')} / "
            f"Total {top_summary.get('mem_total', 'N/A')} {top_summary.get('mem_unit', '')} / "
            f"Free {top_summary.get('mem_free', 'N/A')} {top_summary.get('mem_unit', '')}"
        )

        print(
            f"CPU Summary        : "
            f"us {top_summary.get('us', 'N/A')}% | "
            f"sy {top_summary.get('sy', 'N/A')}% | "
            f"id {top_summary.get('id', 'N/A')}%"
        )

    print()
    print(f"{'PID':<8} {'CPU %':>8} {'MEM %':>8} {'STATE':>8} {'RES':>10} {'VIRT':>10}  Command")
    print("-" * 120)

    if not top_rows:
        print("No top process data returned.")
    else:
        for row in top_rows:
            cpu_pct = row["cpu_pct"]
            cpu_text = health_color(f"{cpu_pct:.2f}", cpu_pct, color_enabled)

            print(
                f"{str(row['pid']):<8} "
                f"{cpu_text:>8} "
                f"{row['mem_pct']:>8.2f} "
                f"{str(row['state']):>8} "
                f"{str(row['res']):>10} "
                f"{str(row['virt']):>10}  "
                f"{row['cmd']}"
            )

    print()
    print(bold("Top Processes - Disk I/O", color_enabled))
    print("-" * 120)

    if iotop_summary:
        print(
            f"Actual Disk Read/Write : "
            f"{iotop_summary.get('actual_disk_read', 'N/A')} / "
            f"{iotop_summary.get('actual_disk_write', 'N/A')}"
        )

        print(
            f"Total Disk Read/Write  : "
            f"{iotop_summary.get('total_disk_read', 'N/A')} / "
            f"{iotop_summary.get('total_disk_write', 'N/A')}"
        )

    print()
    print(f"{'PID':<8} {'Disk Read':>16} {'Disk Write':>16}  Command")
    print("-" * 120)

    if not iotop_rows:
        print("No iotop process data returned.")
    else:
        for row in iotop_rows:
            print(
                f"{str(row['pid']):<8} "
                f"{str(row['disk_read_text']):>16} "
                f"{str(row['disk_write_text']):>16}  "
                f"{row['cmd']}"
            )

def print_dashboard(
    platform,
    platform_type,
    url,
    masked_api_key,
    interval,
    cli_parsed,
    faz_parsed,
    log_forward_data,
    errors,
    show_processes=False,
    top_summary=None,
    top_rows=None,
    iotop_summary=None,
    iotop_rows=None,
    color_enabled=True
):
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    line_width = min(terminal_width, 120)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Prefer CLI data for CPU/memory/disk because it has more detailed disk I/O.
    # Use FAZ monitor data for lograte.
    main_perf = cli_parsed or faz_parsed

    cpu_used = safe_float(main_perf.get("cpu_used"))
    cpu_used_ex_nice = safe_float(main_perf.get("cpu_used_ex_nice"))
    cpu_num = main_perf.get("cpu_num")
    cpu_rows = main_perf.get("cpu_rows", [])

    memory = main_perf.get("memory", {})
    hard_disk = main_perf.get("hard_disk", {})
    flash_disk = main_perf.get("flash_disk", {})

    print(bold("FortiManager / FortiAnalyzer Performance Monitor", color_enabled))
    print("=" * line_width)
    print(f"Detected Type : {cyan(platform, color_enabled)}")
    print(f"Platform Type : {cyan(platform_type, color_enabled)}")
    print(f"URL           : {cyan(url, color_enabled)}")
    print(f"API Key       : {masked_api_key}")
    print(f"Last Updated  : {cyan(now, color_enabled)}")
    print(f"Refresh       : {cyan(str(interval) + ' seconds', color_enabled)}")
    print()

    print(bold("API Calls", color_enabled))
    print("-" * line_width)

    if platform == "FAZ":
        print(f"FAZ monitor performance : {green('enabled', color_enabled)}")
        print(f"CLI system performance  : {green('enabled', color_enabled)}")
        print(f"Log forward status      : {green('enabled', color_enabled)}")
    elif platform == "FMG":
        print(f"FAZ monitor performance : {yellow('skipped - FMG detected', color_enabled)}")
        print(f"CLI system performance  : {green('enabled', color_enabled)}")
        print(f"Log forward status      : {yellow('skipped - FMG detected', color_enabled)}")
    else:
        print(f"FAZ monitor performance : {yellow('skipped - unknown platform', color_enabled)}")
        print(f"CLI system performance  : {green('enabled', color_enabled)}")
        print(f"Log forward status      : {yellow('skipped - unknown platform', color_enabled)}")

    if errors:
        print()
        print(yellow("API warnings/errors:", color_enabled))
        for name, error in errors.items():
            print(f"- {name}: {error}")

    print()
    print(bold("System Summary", color_enabled))
    print("-" * line_width)

    print(
        f"CPU Used       : {cpu_used:>8.2f}%  "
        f"{make_bar(cpu_used, 30, color_enabled)}  "
        f"{health_color(health_label(cpu_used), cpu_used, color_enabled)}"
    )

    print(
        f"CPU Excl Nice  : {cpu_used_ex_nice:>8.2f}%  "
        f"{make_bar(cpu_used_ex_nice, 30, color_enabled)}  "
        f"{health_color(health_label(cpu_used_ex_nice), cpu_used_ex_nice, color_enabled)}"
    )

    print(
        f"CPU Cores      : {cpu_num}"
    )

    print(
        f"Memory Used    : {memory.get('used_percent', 0):>8.2f}%  "
        f"{make_bar(memory.get('used_percent'), 30, color_enabled)}  "
        f"{health_color(health_label(memory.get('used_percent')), memory.get('used_percent'), color_enabled)}  "
        f"({kb_to_gib(memory.get('used_kb')):.2f} GiB / {kb_to_gib(memory.get('total_kb')):.2f} GiB)"
    )

    print(
        f"Hard Disk Used : {hard_disk.get('used_percent', 0):>8.2f}%  "
        f"{make_bar(hard_disk.get('used_percent'), 30, color_enabled)}  "
        f"{health_color(health_label(hard_disk.get('used_percent')), hard_disk.get('used_percent'), color_enabled)}  "
        f"({kb_to_gib(hard_disk.get('used_kb')):.2f} GiB / {kb_to_gib(hard_disk.get('total_kb')):.2f} GiB)"
    )

    print(
        f"Flash Used     : {flash_disk.get('used_percent', 0):>8.2f}%  "
        f"{make_bar(flash_disk.get('used_percent'), 30, color_enabled)}  "
        f"{health_color(health_label(flash_disk.get('used_percent')), flash_disk.get('used_percent'), color_enabled)}  "
        f"({kb_to_gib(flash_disk.get('used_kb')):.2f} GiB / {kb_to_gib(flash_disk.get('total_kb')):.2f} GiB)"
    )

    if faz_parsed:
        receive = faz_parsed.get("receive_lograte", {})
        insert = faz_parsed.get("insert_lograte", {})

        print()
        print(bold("FAZ Lograte", color_enabled))
        print("-" * line_width)
        print(f"Receive Lograte Last 5 sec  : {receive.get('last_5', 0):.4f} logs/sec")
        print(f"Receive Lograte Last 30 sec : {receive.get('last_30', 0):.4f} logs/sec")
        print(f"Receive Lograte Last 60 sec : {receive.get('last_60', 0):.4f} logs/sec")
        print(f"Insert Lograte Last 5 sec   : {insert.get('last_5', 0):.4f} logs/sec")
        print(f"Insert Lograte Last 60 sec  : {insert.get('last_60', 0):.4f} logs/sec")

        if receive.get("last_60", 0) > 0 and insert.get("last_60", 0) < receive.get("last_60", 0) * 0.5:
            print()
            print(yellow("WARNING: Insert lograte is much lower than receive lograte. Possible insertion backlog.", color_enabled))
    else:
        print()
        print(bold("FAZ Lograte", color_enabled))
        print("-" * line_width)
        print(yellow("Not available. This section is FAZ-only and is skipped for FMG.", color_enabled))

    print()
    print(bold("Disk Usage and I/O Details", color_enabled))
    print("-" * line_width)
    print(
        f"{'Disk':<12} "
        f"{'Used':>14} "
        f"{'Total':>14} "
        f"{'Used %':>9} "
        f"{'IO Util':>9} "
        f"{'Queue':>8} "
        f"{'Read KB/s':>10} "
        f"{'Write KB/s':>10} "
        f"{'TPS':>8} "
        f"{'Wait ms':>8} "
        f"{'Svc ms':>8}"
    )
    print("-" * line_width)
    print_disk_io_row("Hard Disk", hard_disk)
    print_disk_io_row("Flash Disk", flash_disk)

    print()
    print(bold("CPU Core Details", color_enabled))
    print("-" * line_width)
    print(
        f"{'Core':<8} "
        f"{'Used':>8} "
        f"{'User':>8} "
        f"{'System':>8} "
        f"{'Nice':>8} "
        f"{'Idle':>8} "
        f"{'IOWait':>8} "
        f"{'IRQ':>8} "
        f"{'SoftIRQ':>8}  "
        f"Usage"
    )
    print("-" * line_width)

    busiest_core = None

    for row in cpu_rows:
        used = safe_float(row.get("used"))

        if busiest_core is None or used > busiest_core["used"]:
            busiest_core = {
                "label": row.get("label"),
                "used": used
            }

        irq = "-" if row.get("irq") is None else f"{safe_float(row.get('irq')):.2f}%"
        softirq = "-" if row.get("softirq") is None else f"{safe_float(row.get('softirq')):.2f}%"

        print(
            f"{row.get('label'):<8} "
            f"{used:>7.2f}% "
            f"{safe_float(row.get('user')):>7.2f}% "
            f"{safe_float(row.get('system')):>7.2f}% "
            f"{safe_float(row.get('nice')):>7.2f}% "
            f"{safe_float(row.get('idle')):>7.2f}% "
            f"{safe_float(row.get('iowait')):>7.2f}% "
            f"{irq:>8} "
            f"{softirq:>8}  "
            f"{make_bar(used, 25, color_enabled)}"
        )

    if busiest_core:
        print()
        msg = f"Busiest Core: {busiest_core['label']} at {busiest_core['used']:.2f}%"
        print(health_color(msg, busiest_core["used"], color_enabled))

    if platform == "FAZ":
        print_log_forward_status(log_forward_data, color_enabled=color_enabled)

    if show_processes:
        print_process_details(
            top_summary=top_summary or {},
            top_rows=top_rows or [],
            iotop_summary=iotop_summary or {},
            iotop_rows=iotop_rows or [],
            color_enabled=color_enabled
        )
    else:
        print()
        print(bold("Process Details", color_enabled))
        print("-" * line_width)
        print("Hidden by default. Restart the script and answer 'y' to show top/iotop process details.")


def main():
    parser = argparse.ArgumentParser(
        description="FMG/FAZ live performance monitor using API key authentication"
    )

    parser.add_argument(
        "--config",
        default="config.ini",
        help="Path to config file. Default: config.ini"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds. Default: 10"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override refresh interval from config file"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal colors"
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Config error: {e}")
        sys.exit(1)

    url = config["url"]
    api_key = config["api_key"]
    verify_ssl = config["verify_ssl"]
    interval = args.interval if args.interval is not None else config["interval"]

    color_enabled = not args.no_color
    masked_api_key = mask_api_key(api_key)

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    show_processes = False

    if not args.once:
        answer = input("Show top/iotop process details? [y/N]: ").strip().lower()
        show_processes = answer in ("y", "yes")
    else:
        answer = input("Show top/iotop process details for this one-time run? [y/N]: ").strip().lower()
        show_processes = answer in ("y", "yes")

    top_n = 50
    display_process_limit = 10

    try:
        status_data = fetch_api_data(
            url=url,
            api_key=api_key,
            body=build_status_body(),
            verify_ssl=verify_ssl,
            timeout=args.timeout
        )

        platform, platform_type = detect_platform(status_data)

        if platform == "UNKNOWN":
            print(yellow("WARNING: Could not clearly detect FMG or FAZ. CLI performance API will still be used.", color_enabled))
            print(f"Detected Platform Type: {platform_type}")
            time.sleep(2)

    except Exception as e:
        print(red("Failed to detect platform using sys/status/.", color_enabled))
        print(str(e))
        sys.exit(1)

    try:
        while True:
            results, errors = run_refresh_calls(
                url=url,
                api_key=api_key,
                platform=platform,
                verify_ssl=verify_ssl,
                timeout=args.timeout,
                show_processes=show_processes,
                top_n=top_n
            )

            cli_parsed = None
            faz_parsed = None
            log_forward_data = None

            top_summary = {}
            top_rows = []
            iotop_summary = {}
            iotop_rows = []

            if "cli_perf" in results:
                cli_parsed = parse_cli_performance(results["cli_perf"])

            if "faz_perf" in results:
                faz_parsed = parse_faz_performance(results["faz_perf"])

            if "log_forward" in results:
                log_forward_data = results["log_forward"]

            if "top" in results:
                top_summary, top_rows = parse_top_processes(
                    results["top"],
                    limit=display_process_limit
                )

            if "iotop" in results:
                iotop_summary, iotop_rows = parse_iotop_processes(
                    results["iotop"],
                    limit=display_process_limit
                )

            clear_screen()

            if not cli_parsed and not faz_parsed:
                print(red("No usable performance data returned.", color_enabled))
                for name, error in errors.items():
                    print(f"- {name}: {error}")
            else:
                print_dashboard(
                    platform=platform,
                    platform_type=platform_type,
                    url=url,
                    masked_api_key=masked_api_key,
                    interval=interval,
                    cli_parsed=cli_parsed,
                    faz_parsed=faz_parsed,
                    log_forward_data=log_forward_data,
                    errors=errors,
                    show_processes=show_processes,
                    top_summary=top_summary,
                    top_rows=top_rows,
                    iotop_summary=iotop_summary,
                    iotop_rows=iotop_rows,
                    color_enabled=color_enabled
                )

            if args.once:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        print("Stopped.")


if __name__ == "__main__":
    main()