#!/usr/bin/env python3
"""
FortiManager-FortiAnalyzer System Performance Monitor
Boxed ANSI dashboard edition.

The API collection and parsing workflow remains the same as the original
monitor. The terminal output uses colored boxes and does not display the API key.

Author: Farhan Ahmed - www.farhan.ch
"""

import argparse
import configparser
import os
import re
import sys
import time
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Iterable, Mapping, Optional

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
        return str(text)
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
        return float(
            str(value)
            .replace(",", "")
            .replace("%", "")
            .replace("KB", "")
            .strip()
        )
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

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not url.endswith("/jsonrpc"):
        url += "/jsonrpc"

    return url


def parse_verify_ssl(value):
    value = str(value).strip()

    if value.lower() in ("true", "yes", "1", "on"):
        return True

    if value.lower() in ("false", "no", "0", "off"):
        return False

    if not os.path.exists(value):
        raise FileNotFoundError(
            f"SSL CA certificate file not found: {value}"
        )

    return value


def load_config(config_file):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")

    config = configparser.ConfigParser()
    config.read(config_file)

    section_name = "config"
    if section_name not in config:
        raise ValueError(
            f"Missing [{section_name}] section in config file"
        )

    device_config = config[section_name]

    url = device_config.get("url", "").strip()
    api_key = device_config.get("api_key", "").strip()
    verify_ssl = parse_verify_ssl(
        device_config.get("verify_ssl", fallback="false")
    )
    interval = device_config.getint("interval", fallback=5)

    if not url:
        raise ValueError(
            f"Missing 'url' under [{section_name}] in config file"
        )

    if not api_key:
        raise ValueError(
            f"Missing 'api_key' under [{section_name}] in config file"
        )

    return {
        "url": normalize_jsonrpc_url(url),
        "api_key": api_key,
        "verify_ssl": verify_ssl,
        "interval": interval,
    }


def build_status_body():
    return {
        "method": "get",
        "params": [{"url": STATUS_API_PATH}],
        "verbose": 1,
        "id": 1,
    }


def build_faz_perf_body():
    return {
        "id": "3",
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "url": FAZ_PERF_API_PATH,
                "apiver": 3,
            }
        ],
    }


def build_cli_perf_body():
    return {
        "id": "4",
        "method": "get",
        "params": [{"url": CLI_PERF_API_PATH}],
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
                    "order-by": "cpu-usage",
                },
            }
        ],
    }


def build_iotop_body(top_n=50):
    return {
        "id": "7",
        "method": "exec",
        "params": [
            {
                "url": IOTOP_API_PATH,
                "data": {"top-n": top_n},
            }
        ],
    }


def build_log_forward_body():
    return {
        "id": "5",
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "url": LOG_FORWARD_API_PATH,
                "apiver": 3,
            }
        ],
    }


def extract_result(payload):
    result = payload.get("result")

    if isinstance(result, list):
        result = result[0] if result else None

    if not result:
        raise RuntimeError(
            f"Missing result in API response: {payload}"
        )

    status = result.get("status")

    if isinstance(status, dict) and status.get("code") not in (0, None):
        raise RuntimeError(f"API error: {status}")

    if "data" not in result:
        raise RuntimeError(
            f"Missing result.data in API response: {payload}"
        )

    return result


def fetch_api_data(url, api_key, body, verify_ssl, timeout):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    response = requests.post(
        url,
        headers=headers,
        json=body,
        verify=verify_ssl,
        timeout=timeout,
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
    platform_type = find_value_by_key(
        status_data,
        "Platform Type",
    )
    combined_text = f"{platform_type} {status_data}".lower()

    if "fortimanager" in combined_text or "fmg" in combined_text:
        return "FMG", str(platform_type or "Unknown")

    if "fortianalyzer" in combined_text or "faz" in combined_text:
        return "FAZ", str(platform_type or "Unknown")

    return "UNKNOWN", str(platform_type or "Unknown")


def parse_used_field(value):
    text = str(value or "")
    kb_match = re.search(
        r"([\d,]+)\s*KB",
        text,
        re.IGNORECASE,
    )
    pct_match = re.search(r"([\d.]+)\s*%", text)

    return {
        "kb": (
            safe_float(kb_match.group(1))
            if kb_match
            else 0.0
        ),
        "percent": (
            safe_float(pct_match.group(1))
            if pct_match
            else 0.0
        ),
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
        match = re.match(
            r"CPU\[(\d+)\] usage",
            str(key),
        )
        if not match:
            continue

        core_index = int(match.group(1))
        details = value.get("Details", {})
        used = safe_float(value.get("Usage"))

        cpu_rows.append(
            {
                "label": f"CPU[{core_index}]",
                "used": used,
                "user": safe_float(details.get("%user")),
                "system": safe_float(details.get("%sys")),
                "nice": safe_float(details.get("%nice")),
                "idle": safe_float(details.get("%idle")),
                "iowait": safe_float(details.get("%iowait")),
                "irq": safe_float(details.get("%irq")),
                "softirq": safe_float(details.get("%softirq")),
                "source": "CLI",
            }
        )

    cpu_rows.sort(key=lambda row: row["label"])

    mem_used = parse_used_field(memory.get("Used"))
    mem_total = parse_total_kb(memory.get("Total"))

    hard_used = parse_used_field(hard_disk.get("Used"))
    hard_total = parse_total_kb(hard_disk.get("Total"))

    flash_used = parse_used_field(flash_disk.get("Used"))
    flash_total = parse_total_kb(flash_disk.get("Total"))

    return {
        "cpu_used": safe_float(cpu.get("Used")),
        "cpu_used_ex_nice": safe_float(
            cpu.get("Used(Excluded NICE)")
        ),
        "cpu_num": int(safe_float(cpu.get("CPU_num"))),
        "cpu_rows": cpu_rows,
        "memory": {
            "used_kb": mem_used["kb"],
            "total_kb": mem_total,
            "used_percent": mem_used["percent"],
        },
        "hard_disk": {
            "used_kb": hard_used["kb"],
            "total_kb": hard_total,
            "used_percent": hard_used["percent"],
            "iostat": hard_disk.get("IOStat", {}),
        },
        "flash_disk": {
            "used_kb": flash_used["kb"],
            "total_kb": flash_total,
            "used_percent": flash_used["percent"],
            "iostat": flash_disk.get("IOStat", {}),
        },
    }


def parse_faz_performance(faz_data):
    cpu = faz_data.get("cpu", {})
    mem = faz_data.get("mem", {})
    disk = faz_data.get("disk", {})
    receive_lograte = faz_data.get("receive-lograte", {})
    insert_lograte = faz_data.get("insert-lograte", {})

    cpu_rows = []

    for index, core_data in enumerate(cpu.get("cores", [])):
        idle = safe_float(core_data.get("idle"))
        used = 100 - idle

        cpu_rows.append(
            {
                "label": f"CPU[{index}]",
                "used": used,
                "user": safe_float(core_data.get("user")),
                "system": safe_float(core_data.get("system")),
                "nice": safe_float(core_data.get("nice")),
                "idle": idle,
                "iowait": safe_float(core_data.get("iowait")),
                "irq": None,
                "softirq": None,
                "source": "FAZ Monitor",
            }
        )

    hard_disk = disk.get("hard-disk", {})
    flash_disk = disk.get("flash-disk", {})

    return {
        "cpu_used": safe_float(cpu.get("used")),
        "cpu_used_ex_nice": safe_float(
            cpu.get("used-excluded-nice")
        ),
        "cpu_num": len(cpu_rows),
        "cpu_rows": cpu_rows,
        "memory": {
            "used_kb": safe_float(mem.get("used")),
            "total_kb": safe_float(mem.get("total")),
            "used_percent": percent(
                mem.get("used"),
                mem.get("total"),
            ),
        },
        "hard_disk": {
            "used_kb": safe_float(hard_disk.get("used")),
            "total_kb": safe_float(hard_disk.get("total")),
            "used_percent": percent(
                hard_disk.get("used"),
                hard_disk.get("total"),
            ),
            "iostat": {
                "%util": hard_disk.get("iostat-util"),
            },
        },
        "flash_disk": {
            "used_kb": safe_float(flash_disk.get("used")),
            "total_kb": safe_float(flash_disk.get("total")),
            "used_percent": percent(
                flash_disk.get("used"),
                flash_disk.get("total"),
            ),
            "iostat": {
                "%util": flash_disk.get("iostat-util"),
            },
        },
        "receive_lograte": {
            "last_5": safe_float(
                receive_lograte.get("last-5sec")
            ),
            "last_30": safe_float(
                receive_lograte.get("last-30sec")
            ),
            "last_60": safe_float(
                receive_lograte.get("last-60sec")
            ),
        },
        "insert_lograte": {
            "last_5": safe_float(
                insert_lograte.get("last-5sec")
            ),
            "last_60": safe_float(
                insert_lograte.get("last-60sec")
            ),
        },
    }


def parse_process_rate(value):
    if value is None:
        return 0.0

    text = str(value).strip().lower()
    text = (
        text.replace("%", "")
        .replace("k/s", "")
        .replace("kb/s", "")
        .strip()
    )

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
    if not isinstance(top_data, dict):
        return {}, []

    processes = top_data.get("lists", [])
    summary = top_data.get("summary", {})
    rows = []

    for item in processes:
        cpu_pct = safe_float(item.get("cpu_pct"))
        mem_pct = safe_float(item.get("mem_pct"))

        rows.append(
            {
                "pid": item.get("pid", "N/A"),
                "cmd": item.get("cmd", "N/A"),
                "state": item.get("state", "N/A"),
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct,
                "res": item.get("res", "N/A"),
                "virt": item.get("virt", "N/A"),
            }
        )

    rows.sort(
        key=lambda row: row["cpu_pct"],
        reverse=True,
    )
    return summary, rows[:limit]


def parse_iotop_processes(iotop_data, limit=10):
    if not isinstance(iotop_data, dict):
        return {}, []

    processes = iotop_data.get("lists", [])
    summary = iotop_data.get("summary", {})
    rows = []

    for item in processes:
        disk_read = parse_process_rate(
            item.get("disk_read")
        )
        disk_write = parse_process_rate(
            item.get("disk_write")
        )

        rows.append(
            {
                "pid": item.get("pid", "N/A"),
                "cmd": item.get("cmd", "N/A"),
                "disk_read": disk_read,
                "disk_write": disk_write,
                "disk_read_text": item.get(
                    "disk_read",
                    "0.00 K/s",
                ),
                "disk_write_text": item.get(
                    "disk_write",
                    "0.00 K/s",
                ),
                "total_io": disk_read + disk_write,
            }
        )

    rows.sort(
        key=lambda row: row["total_io"],
        reverse=True,
    )
    return summary, rows[:limit]


def run_refresh_calls(
    url,
    api_key,
    platform,
    verify_ssl,
    timeout,
    show_processes=False,
    top_n=50,
):
    tasks = {}
    max_workers = 5 if show_processes else 3

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        tasks["cli_perf"] = executor.submit(
            fetch_api_data,
            url,
            api_key,
            build_cli_perf_body(),
            verify_ssl,
            timeout,
        )

        if platform == "FAZ":
            tasks["faz_perf"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_faz_perf_body(),
                verify_ssl,
                timeout,
            )
            tasks["log_forward"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_log_forward_body(),
                verify_ssl,
                timeout,
            )

        if show_processes:
            tasks["top"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_top_body(top_n),
                verify_ssl,
                timeout,
            )
            tasks["iotop"] = executor.submit(
                fetch_api_data,
                url,
                api_key,
                build_iotop_body(top_n),
                verify_ssl,
                timeout,
            )

        results = {}
        errors = {}

        for name, future in tasks.items():
            try:
                results[name] = future.result()
            except Exception as exc:
                errors[name] = str(exc)

    return results, errors

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(value: Any) -> int:
    """Return printable width without ANSI color sequences."""
    return len(ANSI_RE.sub("", str(value)))


def truncate_ansi(value: Any, max_width: int) -> str:
    """Truncate text without breaking ANSI escape sequences."""
    text = str(value)

    if max_width <= 0:
        return ""

    if visible_len(text) <= max_width:
        return text

    if max_width == 1:
        return "…"

    output = []
    printable = 0
    index = 0
    target = max_width - 1

    while index < len(text) and printable < target:
        match = ANSI_RE.match(text, index)
        if match:
            output.append(match.group(0))
            index = match.end()
            continue

        output.append(text[index])
        printable += 1
        index += 1

    output.append("…")

    # Ensure an active ANSI style cannot leak into the box border.
    if "\x1b[" in text:
        output.append("\x1b[0m")

    return "".join(output)


def pad_ansi(value: Any, width: int) -> str:
    """Truncate and right-pad a possibly colored value."""
    text = truncate_ansi(value, width)
    return text + (" " * max(0, width - visible_len(text)))


def get_box_width() -> int:
    """
    Keep boxes inside the current terminal.

    The upper limit preserves the original detailed tables without stretching
    across very wide terminals.
    """
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    return max(50, min(terminal_width, 145))


def box_color(text: str, color_enabled: bool, code: str = "96") -> str:
    return color(text, code, color_enabled)


def print_box(
    title: str,
    lines: Iterable[Any],
    width: int,
    color_enabled: bool = True,
    border_code: str = "96",
) -> None:
    """Print one Unicode box while preserving ANSI-colored content."""
    width = max(20, width)
    inner_width = width - 4

    plain_title = f" {title.strip()} "
    if len(plain_title) > width - 2:
        plain_title = plain_title[: max(1, width - 5)] + "… "

    top_fill = max(0, width - 2 - len(plain_title))
    top = "┌" + plain_title + ("─" * top_fill) + "┐"
    bottom = "└" + ("─" * (width - 2)) + "┘"

    print(box_color(top, color_enabled, border_code))

    rendered_lines = list(lines)
    if not rendered_lines:
        rendered_lines = [""]

    left = box_color("│", color_enabled, border_code)
    right = box_color("│", color_enabled, border_code)

    for line in rendered_lines:
        print(f"{left} {pad_ansi(line, inner_width)} {right}")

    print(box_color(bottom, color_enabled, border_code))
    print()


def health_line(
    label: str,
    value: Any,
    detail: str,
    width: int,
    color_enabled: bool,
) -> str:
    value = safe_float(value)
    bar_width = 30 if width >= 110 else 18 if width >= 85 else 10

    return (
        f"{label:<17}: "
        f"{value:>7.2f}%  "
        f"{make_bar(value, bar_width, color_enabled)}  "
        f"{health_color(health_label(value), value, color_enabled)}"
        f"{detail}"
    )


def disk_table_lines(
    hard_disk: Mapping[str, Any],
    flash_disk: Mapping[str, Any],
    width: int,
    color_enabled: bool,
) -> list[str]:
    inner = width - 4
    rows = [("Hard Disk", hard_disk), ("Flash Disk", flash_disk)]
    lines: list[str] = []

    if inner >= 118:
        lines.append(
            f"{'Disk':<12} {'Used':>12} {'Total':>12} {'Used %':>8} "
            f"{'I/O %':>8} {'Queue':>8} {'Read KB/s':>10} "
            f"{'Write KB/s':>11} {'TPS':>8} {'Wait':>8} {'Svc':>8}"
        )
        lines.append("─" * min(inner, 132))

        for name, disk in rows:
            io = disk.get("iostat", {}) or {}
            used_pct = safe_float(disk.get("used_percent"))
            lines.append(
                f"{name:<12} "
                f"{kb_to_gib(disk.get('used_kb')):>9.2f} GiB "
                f"{kb_to_gib(disk.get('total_kb')):>9.2f} GiB "
                f"{health_color(f'{used_pct:>7.2f}%', used_pct, color_enabled)} "
                f"{safe_float(io.get('%util')):>7.2f}% "
                f"{safe_float(io.get('queue')):>8.2f} "
                f"{safe_float(io.get('r_kB/s')):>10.2f} "
                f"{safe_float(io.get('w_kB/s')):>11.2f} "
                f"{safe_float(io.get('tps')):>8.2f} "
                f"{safe_float(io.get('wait_ms')):>8.2f} "
                f"{safe_float(io.get('svc_ms')):>8.2f}"
            )
    else:
        lines.append(
            f"{'Disk':<12} {'Used/Total':>25} {'Used %':>9} "
            f"{'I/O %':>8} {'Read KB/s':>11} {'Write KB/s':>11}"
        )
        lines.append("─" * min(inner, 86))

        for name, disk in rows:
            io = disk.get("iostat", {}) or {}
            used_pct = safe_float(disk.get("used_percent"))
            capacity = (
                f"{kb_to_gib(disk.get('used_kb')):.2f}/"
                f"{kb_to_gib(disk.get('total_kb')):.2f} GiB"
            )
            lines.append(
                f"{name:<12} {capacity:>25} "
                f"{health_color(f'{used_pct:>8.2f}%', used_pct, color_enabled)} "
                f"{safe_float(io.get('%util')):>7.2f}% "
                f"{safe_float(io.get('r_kB/s')):>11.2f} "
                f"{safe_float(io.get('w_kB/s')):>11.2f}"
            )

    return lines


def cpu_core_lines(
    cpu_rows: Iterable[Mapping[str, Any]],
    width: int,
    color_enabled: bool,
) -> list[str]:
    inner = width - 4
    rows = list(cpu_rows)
    lines: list[str] = []
    busiest: Optional[dict[str, Any]] = None

    if inner >= 105:
        lines.append(
            f"{'Core':<8} {'Used':>8} {'User':>8} {'System':>8} "
            f"{'Nice':>8} {'Idle':>8} {'IOWait':>8} "
            f"{'IRQ':>8} {'SoftIRQ':>8}  Usage"
        )
        lines.append("─" * min(inner, 125))

        for row in rows:
            used = safe_float(row.get("used"))
            if busiest is None or used > busiest["used"]:
                busiest = {"label": row.get("label"), "used": used}

            irq = "-" if row.get("irq") is None else f"{safe_float(row.get('irq')):.2f}%"
            softirq = (
                "-"
                if row.get("softirq") is None
                else f"{safe_float(row.get('softirq')):.2f}%"
            )

            lines.append(
                f"{str(row.get('label')):<8} "
                f"{health_color(f'{used:>7.2f}%', used, color_enabled)} "
                f"{safe_float(row.get('user')):>7.2f}% "
                f"{safe_float(row.get('system')):>7.2f}% "
                f"{safe_float(row.get('nice')):>7.2f}% "
                f"{safe_float(row.get('idle')):>7.2f}% "
                f"{safe_float(row.get('iowait')):>7.2f}% "
                f"{irq:>8} "
                f"{softirq:>8}  "
                f"{make_bar(used, 20, color_enabled)}"
            )
    else:
        lines.append(
            f"{'Core':<9} {'Used':>9} {'User':>9} "
            f"{'System':>9} {'IOWait':>9}  Usage"
        )
        lines.append("─" * min(inner, 80))

        for row in rows:
            used = safe_float(row.get("used"))
            if busiest is None or used > busiest["used"]:
                busiest = {"label": row.get("label"), "used": used}

            lines.append(
                f"{str(row.get('label')):<9} "
                f"{health_color(f'{used:>8.2f}%', used, color_enabled)} "
                f"{safe_float(row.get('user')):>8.2f}% "
                f"{safe_float(row.get('system')):>8.2f}% "
                f"{safe_float(row.get('iowait')):>8.2f}%  "
                f"{make_bar(used, 15, color_enabled)}"
            )

    if not rows:
        lines.append(yellow("No CPU core details returned.", color_enabled))
    elif busiest:
        lines.extend(
            [
                "",
                health_color(
                    f"Busiest Core: {busiest['label']} at {busiest['used']:.2f}%",
                    busiest["used"],
                    color_enabled,
                ),
            ]
        )

    return lines


def log_forward_lines(
    log_forward_data: Any,
    width: int,
    color_enabled: bool,
) -> list[str]:
    if not isinstance(log_forward_data, list):
        return [
            yellow(
                "Log forwarding status unavailable or returned an unexpected format.",
                color_enabled,
            )
        ]

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

    lines = [
        f"Visible Forwarders : {connected + disconnected}",
        f"Connected          : {green(str(connected), color_enabled)}",
        f"Disconnected       : {red(str(disconnected), color_enabled)}",
        f"Total Lograte      : {total_lograte:.4f} logs/sec",
        "",
        f"{'ID':<8} {'Status':<16} {'Lograte':>18}  Comment",
        "─" * min(width - 4, 100),
    ]

    for item in log_forward_data:
        forwarder_id = item.get("id", "N/A")
        status = str(item.get("status", "unknown")).lower()
        lograte = safe_float(item.get("lograte"))

        if status == "connected":
            status_text = green("connected", color_enabled)
            comment = (
                "Forwarding logs"
                if lograte > 0
                else "Connected, but current forwarding rate is 0"
            )
        elif status == "disconnected":
            status_text = red("disconnected", color_enabled)
            comment = "Disconnected - check destination/connectivity"
        else:
            status_text = yellow(status, color_enabled)
            comment = "Unknown status returned by device"

        lines.append(
            f"{str(forwarder_id):<8} "
            f"{status_text:<16} "
            f"{lograte:>12.4f} logs/sec  "
            f"{comment}"
        )

    return lines


def cpu_process_lines(
    summary: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    width: int,
    color_enabled: bool,
) -> list[str]:
    lines: list[str] = []

    if summary:
        lines.extend(
            [
                (
                    "Load Avg 1m/5m/15m : "
                    f"{summary.get('load_avg_1', 'N/A')} / "
                    f"{summary.get('load_avg_5', 'N/A')} / "
                    f"{summary.get('load_avg_15', 'N/A')}"
                ),
                (
                    "Memory             : "
                    f"Used {summary.get('mem_used', 'N/A')} "
                    f"{summary.get('mem_unit', '')} / "
                    f"Total {summary.get('mem_total', 'N/A')} "
                    f"{summary.get('mem_unit', '')} / "
                    f"Free {summary.get('mem_free', 'N/A')} "
                    f"{summary.get('mem_unit', '')}"
                ),
                (
                    "CPU Summary        : "
                    f"us {summary.get('us', 'N/A')}% | "
                    f"sy {summary.get('sy', 'N/A')}% | "
                    f"id {summary.get('id', 'N/A')}%"
                ),
                "",
            ]
        )

    lines.extend(
        [
            f"{'PID':<8} {'CPU %':>9} {'MEM %':>9} "
            f"{'STATE':>8} {'RES':>10} {'VIRT':>10}  Command",
            "─" * min(width - 4, 105),
        ]
    )

    row_count = 0
    for row in rows:
        row_count += 1
        cpu_pct = safe_float(row.get("cpu_pct"))
        lines.append(
            f"{str(row.get('pid', 'N/A')):<8} "
            f"{health_color(f'{cpu_pct:>8.2f}', cpu_pct, color_enabled)} "
            f"{safe_float(row.get('mem_pct')):>9.2f} "
            f"{str(row.get('state', 'N/A')):>8} "
            f"{str(row.get('res', 'N/A')):>10} "
            f"{str(row.get('virt', 'N/A')):>10}  "
            f"{row.get('cmd', 'N/A')}"
        )

    if row_count == 0:
        lines.append("No top process data returned.")

    return lines


def io_process_lines(
    summary: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    width: int,
) -> list[str]:
    lines: list[str] = []

    if summary:
        lines.extend(
            [
                (
                    "Actual Disk Read/Write : "
                    f"{summary.get('actual_disk_read', 'N/A')} / "
                    f"{summary.get('actual_disk_write', 'N/A')}"
                ),
                (
                    "Total Disk Read/Write  : "
                    f"{summary.get('total_disk_read', 'N/A')} / "
                    f"{summary.get('total_disk_write', 'N/A')}"
                ),
                "",
            ]
        )

    lines.extend(
        [
            f"{'PID':<8} {'Disk Read':>16} {'Disk Write':>16}  Command",
            "─" * min(width - 4, 80),
        ]
    )

    row_count = 0
    for row in rows:
        row_count += 1
        lines.append(
            f"{str(row.get('pid', 'N/A')):<8} "
            f"{str(row.get('disk_read_text', '0.00 K/s')):>16} "
            f"{str(row.get('disk_write_text', '0.00 K/s')):>16}  "
            f"{row.get('cmd', 'N/A')}"
        )

    if row_count == 0:
        lines.append("No iotop process data returned.")

    return lines


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
    color_enabled=True,
):
    """
    Boxed replacement for the original print_dashboard().

    Data preference and behavior are intentionally identical to the original:
    CLI data is preferred for CPU/memory/disk, while the FAZ monitor response
    supplies log-rate information.
    """
    width = get_box_width()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    main_perf = cli_parsed or faz_parsed
    cpu_used = safe_float(main_perf.get("cpu_used"))
    cpu_used_ex_nice = safe_float(main_perf.get("cpu_used_ex_nice"))
    cpu_num = main_perf.get("cpu_num")
    cpu_rows = main_perf.get("cpu_rows", [])

    memory = main_perf.get("memory", {}) or {}
    hard_disk = main_perf.get("hard_disk", {}) or {}
    flash_disk = main_perf.get("flash_disk", {}) or {}

    print_box(
        "FMG / FAZ PERFORMANCE MONITOR",
        [
            f"Detected Type : {cyan(platform, color_enabled)}",
            f"Platform Type : {cyan(platform_type, color_enabled)}",
            f"URL           : {cyan(url, color_enabled)}",
            f"Last Updated  : {cyan(now, color_enabled)}",
            f"Refresh       : {cyan(str(interval) + ' seconds', color_enabled)}",
        ],
        width,
        color_enabled,
        border_code="94",
    )

    if platform == "FAZ":
        api_lines = [
            f"FAZ monitor performance : {green('enabled', color_enabled)}",
            f"CLI system performance  : {green('enabled', color_enabled)}",
            f"Log forward status      : {green('enabled', color_enabled)}",
        ]
    elif platform == "FMG":
        api_lines = [
            f"FAZ monitor performance : {yellow('skipped - FMG detected', color_enabled)}",
            f"CLI system performance  : {green('enabled', color_enabled)}",
            f"Log forward status      : {yellow('skipped - FMG detected', color_enabled)}",
        ]
    else:
        api_lines = [
            f"FAZ monitor performance : {yellow('skipped - unknown platform', color_enabled)}",
            f"CLI system performance  : {green('enabled', color_enabled)}",
            f"Log forward status      : {yellow('skipped - unknown platform', color_enabled)}",
        ]

    print_box("API CALLS", api_lines, width, color_enabled)

    if errors:
        warning_lines = [
            yellow(f"{name}: {error}", color_enabled)
            for name, error in errors.items()
        ]
        print_box(
            "API WARNINGS / ERRORS",
            warning_lines,
            width,
            color_enabled,
            border_code="93",
        )

    print_box(
        "SYSTEM SUMMARY",
        [
            health_line("CPU Used", cpu_used, "", width, color_enabled),
            health_line(
                "CPU Excl. NICE",
                cpu_used_ex_nice,
                "",
                width,
                color_enabled,
            ),
            f"{'CPU Cores':<17}: {cpu_num}",
            health_line(
                "Memory Used",
                memory.get("used_percent", 0),
                (
                    f"  ({kb_to_gib(memory.get('used_kb')):.2f} GiB / "
                    f"{kb_to_gib(memory.get('total_kb')):.2f} GiB)"
                ),
                width,
                color_enabled,
            ),
            health_line(
                "Hard Disk Used",
                hard_disk.get("used_percent", 0),
                (
                    f"  ({kb_to_gib(hard_disk.get('used_kb')):.2f} GiB / "
                    f"{kb_to_gib(hard_disk.get('total_kb')):.2f} GiB)"
                ),
                width,
                color_enabled,
            ),
            health_line(
                "Flash Used",
                flash_disk.get("used_percent", 0),
                (
                    f"  ({kb_to_gib(flash_disk.get('used_kb')):.2f} GiB / "
                    f"{kb_to_gib(flash_disk.get('total_kb')):.2f} GiB)"
                ),
                width,
                color_enabled,
            ),
        ],
        width,
        color_enabled,
        border_code="92",
    )

    if faz_parsed:
        receive = faz_parsed.get("receive_lograte", {}) or {}
        insert = faz_parsed.get("insert_lograte", {}) or {}

        lograte_lines = [
            f"Receive Lograte Last 5 sec  : {receive.get('last_5', 0):.4f} logs/sec",
            f"Receive Lograte Last 30 sec : {receive.get('last_30', 0):.4f} logs/sec",
            f"Receive Lograte Last 60 sec : {receive.get('last_60', 0):.4f} logs/sec",
            f"Insert Lograte Last 5 sec   : {insert.get('last_5', 0):.4f} logs/sec",
            f"Insert Lograte Last 60 sec  : {insert.get('last_60', 0):.4f} logs/sec",
        ]

        if (
            receive.get("last_60", 0) > 0
            and insert.get("last_60", 0) < receive.get("last_60", 0) * 0.5
        ):
            lograte_lines.extend(
                [
                    "",
                    yellow(
                        "WARNING: Insert lograte is much lower than receive "
                        "lograte. Possible insertion backlog.",
                        color_enabled,
                    ),
                ]
            )
    else:
        lograte_lines = [
            yellow(
                "Not available. This section is FAZ-only and is skipped for FMG.",
                color_enabled,
            )
        ]

    print_box("FAZ LOGRATE", lograte_lines, width, color_enabled)

    print_box(
        "DISK USAGE AND I/O DETAILS",
        disk_table_lines(hard_disk, flash_disk, width, color_enabled),
        width,
        color_enabled,
    )

    print_box(
        "CPU CORE DETAILS",
        cpu_core_lines(cpu_rows, width, color_enabled),
        width,
        color_enabled,
    )

    if platform == "FAZ":
        print_box(
            "LOG FORWARDING STATUS",
            log_forward_lines(log_forward_data, width, color_enabled),
            width,
            color_enabled,
        )

    if show_processes:
        print_box(
            "TOP PROCESSES - CPU",
            cpu_process_lines(
                top_summary or {},
                top_rows or [],
                width,
                color_enabled,
            ),
            width,
            color_enabled,
            border_code="95",
        )
        print_box(
            "TOP PROCESSES - DISK I/O",
            io_process_lines(
                iotop_summary or {},
                iotop_rows or [],
                width,
            ),
            width,
            color_enabled,
            border_code="95",
        )
    else:
        print_box(
            "PROCESS DETAILS",
            [
                "Hidden by default. Restart with --processes to display "
                "top and iotop process details."
            ],
            width,
            color_enabled,
            border_code="90",
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "FMG/FAZ live performance monitor "
            "using API key authentication"
        )
    )
    parser.add_argument(
        "--config",
        default="config.ini",
        help="Path to config file. Default: config.ini",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds. Default: 10",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override refresh interval from config file",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal colors",
    )
    parser.add_argument(
        "--processes",
        action="store_true",
        help=(
            "Show top/iotop process details "
            "for CPU and disk I/O"
        ),
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=50,
        help=(
            "Number of processes to request from "
            "top/iotop API. Default: 50"
        ),
    )
    parser.add_argument(
        "--process-limit",
        type=int,
        default=10,
        help=(
            "Number of processes to display "
            "in output. Default: 10"
        ),
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"Config error: {exc}")
        sys.exit(1)

    url = config["url"]
    api_key = config["api_key"]
    verify_ssl = config["verify_ssl"]
    interval = (
        args.interval
        if args.interval is not None
        else config["interval"]
    )

    color_enabled = not args.no_color

    if not verify_ssl:
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

    show_processes = args.processes
    top_n = args.top_n
    display_process_limit = args.process_limit

    try:
        status_data = fetch_api_data(
            url=url,
            api_key=api_key,
            body=build_status_body(),
            verify_ssl=verify_ssl,
            timeout=args.timeout,
        )
        platform, platform_type = detect_platform(
            status_data
        )

        if platform == "UNKNOWN":
            print(
                yellow(
                    "WARNING: Could not clearly detect FMG "
                    "or FAZ. CLI performance API will "
                    "still be used.",
                    color_enabled,
                )
            )
            print(
                f"Detected Platform Type: {platform_type}"
            )
            time.sleep(2)

    except Exception as exc:
        print(
            red(
                "Failed to detect platform using "
                "sys/status/.",
                color_enabled,
            )
        )
        print(str(exc))
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
                top_n=top_n,
            )

            cli_parsed = None
            faz_parsed = None
            log_forward_data = None
            top_summary = {}
            top_rows = []
            iotop_summary = {}
            iotop_rows = []

            if "cli_perf" in results:
                cli_parsed = parse_cli_performance(
                    results["cli_perf"]
                )

            if "faz_perf" in results:
                faz_parsed = parse_faz_performance(
                    results["faz_perf"]
                )

            if "log_forward" in results:
                log_forward_data = results["log_forward"]

            if "top" in results:
                top_summary, top_rows = (
                    parse_top_processes(
                        results["top"],
                        limit=display_process_limit,
                    )
                )

            if "iotop" in results:
                iotop_summary, iotop_rows = (
                    parse_iotop_processes(
                        results["iotop"],
                        limit=display_process_limit,
                    )
                )

            clear_screen()

            if not cli_parsed and not faz_parsed:
                print(
                    red(
                        "No usable performance data returned.",
                        color_enabled,
                    )
                )
                for name, error in errors.items():
                    print(f"- {name}: {error}")
            else:
                print_dashboard(
                    platform=platform,
                    platform_type=platform_type,
                    url=url,
                    masked_api_key=None,
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
                    color_enabled=color_enabled,
                )

            if args.once:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        print("Stopped.")


if __name__ == "__main__":
    main()
