#!/usr/bin/env python3
"""
FMG/FAZ TAC Report Analyzer
===========================

Terminal-first TAC report analyzer for FortiManager and FortiAnalyzer.

Default behavior:
    python tac_analyzer.py <tac-report.tar.gz|folder|txt|log>

It prints a human-readable TXT analysis directly to the terminal.
It does NOT save output files unless --save-output or --save-consolidated is used.

Supported inputs:
    - .tar.gz / .tgz / .tar
    - .zip
    - single .gz text file
    - extracted TAC folder
    - consolidated .txt/.log report

Optional:
    --json                  Print JSON to terminal instead of TXT
    --save-output           Save TXT + JSON reports
    --save-consolidated     Save consolidated readable TAC text
"""

from __future__ import annotations

import argparse
import dataclasses
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

TEXT_LIKE_EXTENSIONS = {
    ".txt", ".log", ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
    ".csv", ".out", ".err", ".debug", ".diag", ".dump", ".md", ".html", ".htm",
    ".properties", ".env", ".license", ".lic", ".lst", ".stat", ".status",
    ".route", ".routes", ".ip", ".table", ".sql", ".trace", ".trc",
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"}
SEVERITY_RANK = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}
SEVERITY_ICON = {"CRIT": "[CRIT]", "WARN": "[WARN]", "INFO": "[INFO]", "OK": "[OK]"}

DEFAULT_MAX_FILE_MB = 150
DEFAULT_MAX_TOTAL_MB = 2048
DEFAULT_CONTEXT_LINES = 2
DEFAULT_FINDING_LIMIT_PER_RULE = 50


# -----------------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------------

@dataclasses.dataclass
class LogFile:
    name: str
    path: str
    text: str
    size_bytes: int
    sha256: str


@dataclasses.dataclass
class Evidence:
    file: str
    line: int
    text: str
    context: List[str]


@dataclasses.dataclass
class Finding:
    severity: str
    category: str
    title: str
    source: str
    evidence: Evidence
    recommendation: str
    rule_id: str


@dataclasses.dataclass
class Fact:
    name: str
    value: str
    source: str
    line: int


@dataclasses.dataclass
class Rule:
    rule_id: str
    severity: str
    category: str
    title: str
    patterns: List[re.Pattern]
    recommendation: str
    negative_patterns: Optional[List[re.Pattern]] = None
    max_findings: int = DEFAULT_FINDING_LIMIT_PER_RULE


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------

def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)

    while "\b" in text:
        new_text = re.sub(r".?\x08", "", text)
        if new_text == text:
            break
        text = new_text

    return text


def safe_decode(data: bytes) -> Optional[str]:
    if not data:
        return ""

    sample = data[:8192]

    if b"\x00" in sample:
        return None

    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    if sample and control / len(sample) > 0.25:
        return None

    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = data.decode(enc, errors="replace")
            if text and text.count("\ufffd") / max(len(text), 1) > 0.05:
                continue
            return normalize_text(text)
        except Exception:
            pass

    return None


def is_text_candidate(name: str) -> bool:
    lower = name.lower()
    path = Path(lower)

    if path.suffix in TEXT_LIKE_EXTENSIONS:
        return True

    if not path.suffix and not lower.endswith(tuple(ARCHIVE_EXTENSIONS)):
        return True

    common_tokens = (
        "sysinfo", "get system", "diagnose", "diag", "show", "execute", "fnsysctl",
        "dmesg", "messages", "crashlog", "eventlog", "miglog", "faz", "fmg",
        "postgres", "clickhouse", "redis", "fgfm", "fortilog", "sqllog", "oftpd",
    )

    return any(token in lower for token in common_tokens)


def command_name_from_path(path: str) -> str:
    name = Path(path).name.strip()

    known_suffixes = [
        ".tar.gz", ".tgz", ".tar", ".zip", ".gz", ".bz2", ".xz",
        ".txt", ".log", ".conf", ".cfg", ".out", ".err", ".debug", ".diag", ".dump",
    ]

    lower = name.lower()
    for suffix in known_suffixes:
        if lower.endswith(suffix):
            name = name[: -len(suffix)]
            lower = name.lower()
            break

    name = name.replace("_", " ").replace("-", " ")
    name = re.sub(r"\s+", " ", name).strip()

    return name or Path(path).stem or "unknown"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def line_context(lines: List[str], idx: int, context_lines: int) -> List[str]:
    start = max(0, idx - context_lines)
    end = min(len(lines), idx + context_lines + 1)
    return [f"{i + 1}: {lines[i]}" for i in range(start, end)]


def truncate(value: str, max_len: int = 500) -> str:
    value = value.strip()
    return value if len(value) <= max_len else value[: max_len - 3] + "..."


def compile_patterns(patterns: Iterable[str]) -> List[re.Pattern]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


# -----------------------------------------------------------------------------
# Input loading
# -----------------------------------------------------------------------------

class TACLoader:
    def __init__(
        self,
        max_file_mb: int = DEFAULT_MAX_FILE_MB,
        max_total_mb: int = DEFAULT_MAX_TOTAL_MB,
    ):
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.max_total_bytes = max_total_mb * 1024 * 1024
        self.total_bytes = 0
        self.skipped: List[Dict[str, str]] = []

    def load(self, input_path: Path) -> List[LogFile]:
        if not input_path.exists():
            raise FileNotFoundError(f"Input path does not exist: {input_path}")

        if input_path.is_dir():
            files = list(self._load_folder(input_path))
        elif zipfile.is_zipfile(input_path):
            files = list(self._load_zip(input_path))
        elif tarfile.is_tarfile(input_path):
            files = list(self._load_tar(input_path))
        elif input_path.suffix.lower() == ".gz":
            files = list(self._load_single_gzip(input_path))
        else:
            files = list(self._load_single_file(input_path))

        unique: Dict[str, LogFile] = {}
        for lf in files:
            unique.setdefault(lf.sha256, lf)

        return list(unique.values())

    def _read_allowed(self, name: str, size: int) -> bool:
        if size > self.max_file_bytes:
            self.skipped.append({"path": name, "reason": f"file too large: {size} bytes"})
            return False

        if self.total_bytes + size > self.max_total_bytes:
            self.skipped.append({"path": name, "reason": "max total read size reached"})
            return False

        return True

    def _make_log_file(self, path: str, data: bytes) -> Optional[LogFile]:
        if not self._read_allowed(path, len(data)):
            return None

        if not is_text_candidate(path):
            if Path(path).suffix and len(data) > 5 * 1024 * 1024:
                self.skipped.append({"path": path, "reason": "not text-like"})
                return None

        text = safe_decode(data)
        if text is None:
            self.skipped.append({"path": path, "reason": "binary or undecodable"})
            return None

        self.total_bytes += len(data)

        return LogFile(
            name=command_name_from_path(path),
            path=path,
            text=text,
            size_bytes=len(data),
            sha256=sha256_bytes(data),
        )

    def _load_single_file(self, input_path: Path) -> Iterator[LogFile]:
        data = input_path.read_bytes()
        lf = self._make_log_file(str(input_path), data)
        if lf:
            yield lf

    def _load_single_gzip(self, input_path: Path) -> Iterator[LogFile]:
        try:
            with gzip.open(input_path, "rb") as fh:
                data = fh.read(self.max_file_bytes + 1)

            lf = self._make_log_file(str(input_path), data)
            if lf:
                yield lf

        except OSError:
            self.skipped.append({"path": str(input_path), "reason": "invalid gzip file"})

    def _load_folder(self, folder: Path) -> Iterator[LogFile]:
        for root, _, filenames in os.walk(folder):
            for filename in filenames:
                path = Path(root) / filename

                try:
                    if path.is_symlink():
                        self.skipped.append({"path": str(path), "reason": "symlink skipped"})
                        continue

                    data = path.read_bytes()
                    lf = self._make_log_file(str(path.relative_to(folder)), data)

                    if lf:
                        yield lf

                except Exception as exc:
                    self.skipped.append({"path": str(path), "reason": f"read error: {exc}"})

    def _load_zip(self, input_path: Path) -> Iterator[LogFile]:
        with zipfile.ZipFile(input_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                if info.file_size > self.max_file_bytes:
                    self.skipped.append(
                        {"path": info.filename, "reason": f"file too large: {info.file_size} bytes"}
                    )
                    continue

                try:
                    with zf.open(info, "r") as fh:
                        data = fh.read(self.max_file_bytes + 1)

                    lf = self._make_log_file(info.filename, data)

                    if lf:
                        yield lf

                except Exception as exc:
                    self.skipped.append({"path": info.filename, "reason": f"zip read error: {exc}"})

    def _load_tar(self, input_path: Path) -> Iterator[LogFile]:
        with tarfile.open(input_path, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue

                if member.size > self.max_file_bytes:
                    self.skipped.append(
                        {"path": member.name, "reason": f"file too large: {member.size} bytes"}
                    )
                    continue

                try:
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue

                    data = fh.read(self.max_file_bytes + 1)
                    lf = self._make_log_file(member.name, data)

                    if lf:
                        yield lf

                except Exception as exc:
                    self.skipped.append({"path": member.name, "reason": f"tar read error: {exc}"})


# -----------------------------------------------------------------------------
# Rules
# -----------------------------------------------------------------------------

def build_rules() -> List[Rule]:
    return [
        Rule(
            rule_id="CRASH_CORE_PANIC",
            severity="CRIT",
            category="Crash / Core Dump",
            title="Crash, panic, segfault, watchdog, or core dump evidence found",
            patterns=compile_patterns([
                r"\bkernel panic\b",
                r"\bpanic:\b",
                r"\bsegmentation fault\b",
                r"\bsegfault\b",
                r"\bcore dumped\b",
                r"\bcoredump\b",
                r"\bcore file\b",
                r"\bwatchdog\b.*\b(?:timeout|reset|bite|panic)\b",
                r"\bfatal signal\b",
                r"\bbacktrace\b.*\b(?:crash|panic|fatal|segfault)\b",
                r"\bdaemon\b.*\b(?:crashed|crash|aborted|abort)\b",
            ]),
            negative_patterns=compile_patterns([
                r"show daemon thread backtrace",
                r"need run ['\"]?backtrace",
                r"backtrace command",
            ]),
            recommendation=(
                "Collect crash/core files if present, confirm timestamp correlation, "
                "and check known issues for the exact FMG/FAZ build."
            ),
        ),

        Rule(
            rule_id="OOM_MEMORY_FAILURE",
            severity="CRIT",
            category="Memory",
            title="Out-of-memory or allocation failure evidence found",
            patterns=compile_patterns([
                r"\bout of memory\b",
                r"\boom-killer\b",
                r"\bkilled process\b.*\bout of memory\b",
                r"\bmemory allocation failed\b",
                r"\bmalloc failed\b",
                r"\bcannot allocate memory\b",
                r"\bpage allocation failure\b",
                r"\bswap.*\bexhausted\b",
            ]),
            recommendation=(
                "Review memory pressure, swap usage, process memory, scheduled reports, "
                "log indexing load, and VM sizing."
            ),
        ),

        Rule(
            rule_id="DISK_FILESYSTEM_FAILURE",
            severity="CRIT",
            category="Disk / Filesystem",
            title="Disk, filesystem, or storage error evidence found",
            patterns=compile_patterns([
                r"\bno space left on device\b",
                r"\bfilesystem.*\bfull\b",
                r"\bdisk.*\bfull\b",
                r"\binode.*\bfull\b",
                r"\bread-only file system\b",
                r"\bI/O error\b",
                r"\bext[234]-fs error\b",
                r"\bXFS.*\berror\b",
                r"\bjournal.*\babort",
                r"\bblk_update_request.*\bI/O error\b",
                r"\bbuffer I/O error\b",
                r"\bwrite failed.*\b(?:disk|device|filesystem)\b",
            ]),
            recommendation=(
                "Check df/df -i, storage health, snapshots, hypervisor datastore health, "
                "and log/database retention before cleanup."
            ),
        ),

        Rule(
            rule_id="RAID_SMART_STORAGE_HEALTH",
            severity="CRIT",
            category="Disk / Hardware",
            title="RAID, SMART, bad sector, or disk health issue found",
            patterns=compile_patterns([
                r"\bSMART.*\b(?:failed|failure|prefail|bad)\b",
                r"\bbad sectors?\b",
                r"\bmedium error\b",
                r"\bRAID.*\b(?:degraded|failed|rebuild|critical)\b",
                r"\bmdadm.*\b(?:degraded|failed)\b",
                r"\bdisk.*\b(?:failed|failure|predictive)\b",
            ]),
            recommendation=(
                "Escalate hardware/storage health, validate RAID/SMART state, and preserve logs "
                "before disk replacement or rebuild."
            ),
        ),

        Rule(
            rule_id="DB_POSTGRES_CLICKHOUSE_REDIS",
            severity="CRIT",
            category="Database",
            title="Database service error/corruption evidence found",
            patterns=compile_patterns([
                r"\bpostgres\b.*\b(?:FATAL|PANIC|ERROR|corrupt|could not|failed|timeout|terminated)\b",
                r"\bclickhouse\b.*\b(?:exception|error|failed|corrupt|timeout|cannot|broken)\b",
                r"\bredis\b.*\b(?:error|failed|MISCONF|OOM|cannot|timeout)\b",
                r"\bdatabase\b.*\b(?:corrupt|corruption|failed|failure|panic|inconsistent|deadlock)\b",
                r"\brelation .* does not exist\b",
                r"\bduplicate key value violates\b",
                r"\bdeadlock detected\b",
            ]),
            negative_patterns=compile_patterns([
                r"sqlfilter",
                r"set sqlfilter",
                r"handler name",
                r"rule name",
                r"event handler",
                r"\bpostgres\b.*\bLISTEN\b",
                r"\bclickhouse\b.*\bLISTEN\b",
                r"\bredis-server\b.*\bLISTEN\b",
            ]),
            recommendation=(
                "Check DB process health, storage latency, recent upgrade/migration, "
                "and DB-specific repair guidance before manual DB changes."
            ),
        ),

        Rule(
            rule_id="SERVICE_DAEMON_FAILURE",
            severity="WARN",
            category="Service / Daemon",
            title="FMG/FAZ daemon/service failure evidence found",
            patterns=compile_patterns([
                r"\b(?:fgfmd|fgfmsd|dvmdb|dvmcore|fgdsvr|httpd|apache|nginx|fortilogd|logfiled|sqllogd|siemdbd|fazsvcd|oftpd|fabricsyncd)\b.*\b(?:failed|failure|crash|crashed|abort|aborted|restart|restarted|timeout|not running|dead)\b",
                r"\bservice\b.*\b(?:failed|not running|dead|timeout)\b",
                r"\bdaemon\b.*\b(?:failed|not running|dead|timeout)\b",
            ]),
            negative_patterns=compile_patterns([
                r"\b0\s+failed\b",
                r"failed\s*[:=]\s*0\b",
                r"error\s*[:=]\s*0\b",
                r"\bLISTEN\b",
                r"\bESTABLISHED\b",
                r"process list",
                r"system process",
            ]),
            recommendation=(
                "Confirm service state, restart history, and timestamp correlation with user impact "
                "before restarting services."
            ),
        ),

        Rule(
            rule_id="FMG_ADOM_WORKSPACE_LOCK",
            severity="WARN",
            category="FortiManager / ADOM",
            title="ADOM/workspace lock or revision conflict evidence found",
            patterns=compile_patterns([
                r"\badom\b.*\b(?:locked|lock conflict|workspace lock|unable to lock|lock failed)\b",
                r"\bworkspace\b.*\b(?:locked|lock conflict|unable to lock|lock failed)\b",
                r"\brevision\b.*\b(?:conflict|failed|locked)\b",
            ]),
            negative_patterns=compile_patterns([
                r"^\s*set\s+adom-lock\b",
                r"^\s*set\s+workspace-mode\b",
                r"\badom-lock\s*[:=]\s*(?:disable|enable)\b",
            ]),
            recommendation=(
                "Check active admin sessions, workspace mode, locked ADOMs, and pending "
                "install/revision operations."
            ),
        ),

        Rule(
            rule_id="FMG_INSTALL_PACKAGE_FAILURE",
            severity="CRIT",
            category="FortiManager / Install",
            title="Policy/package install or config push failure evidence found",
            patterns=compile_patterns([
                r"\binstall\b.*\b(?:failed|failure|error|aborted|timeout)\b",
                r"\bpackage\b.*\b(?:install|push|deployment)\b.*\b(?:failed|failure|error)\b",
                r"\bcopy device db\b.*\b(?:failed|failure|error)\b",
                r"\bvalidation\b.*\b(?:failed|error)\b",
                r"\bconflict\b.*\b(?:install|policy|package|object)\b",
                r"\bscript\b.*\b(?:failed|failure|timeout|error)\b",
                r"\bcli template\b.*\b(?:failed|failure|error)\b",
            ]),
            negative_patterns=compile_patterns([
                r"install preview",
                r"install log.*no error",
                r"\bfailed\s*[:=]\s*0\b",
                r"\berror\s*[:=]\s*0\b",
            ]),
            recommendation=(
                "Review install logs, policy/object validation errors, device status, workspace locks, "
                "and exact failed command/object."
            ),
        ),

        Rule(
            rule_id="FMG_DEVICE_MANAGER_FGFM",
            severity="WARN",
            category="FortiManager / Device Manager",
            title="Device manager, FGFM, or managed-device communication issue found",
            patterns=compile_patterns([
                r"\bfgfm\b.*\b(?:failed|failure|disconnect|disconnected|timeout|closed|denied|unauthori[sz]ed|certificate|ssl|tls)\b",
                r"\bfgfmd\b.*\b(?:failed|failure|disconnect|disconnected|timeout|closed|denied|unauthori[sz]ed|certificate|ssl|tls)\b",
                r"\bdevice\b.*\b(?:offline|unreachable|not reachable|unauthori[sz]ed|failed to connect|connection failed)\b",
                r"\bretrieve\b.*\b(?:failed|failure|timeout)\b",
                r"\bfgfm.*\bport\s*541\b.*\b(?:failed|timeout|refused|closed)\b",
            ]),
            negative_patterns=compile_patterns([
                r"fgfm ssl proxy",
                r"\bLISTEN\b",
                r"\bESTABLISHED\b",
                r"\b0\s+failed\b",
                r"failed\s*[:=]\s*0\b",
                r"error\s*[:=]\s*0\b",
            ]),
            recommendation=(
                "Validate FGFM connectivity, certificates, serial/authorization state, device status, "
                "and TCP/541 reachability."
            ),
        ),

        Rule(
            rule_id="FAZ_LOG_RECEIVE_INGESTION",
            severity="CRIT",
            category="FortiAnalyzer / Log Receive",
            title="Log receive, OFTP, fortilogd, or ingestion issue found",
            patterns=compile_patterns([
                r"\bfortilogd\b.*\b(?:failed|failure|error|dropped|drop|timeout|blocked|not running|restart)\b",
                r"\boftpd\b.*\b(?:failed|failure|error|dropped|drop|timeout|blocked|not running|restart)\b",
                r"\blog\b.*\b(?:dropped|dropping|lost|not received|receive failed|ingestion failed|ingest failed)\b",
                r"\b(?:msg-dropped|ack-drop|ack-err|parse_msg|build_resp)\b\s*[:=]\s*[1-9]\d*\b",
                r"\blog rate\b.*\b(?:exceed|exceeded|drop|dropped|throttle|limited)\b",
            ]),
            negative_patterns=compile_patterns([
                r"\b(?:dropped|drop|failed|error|msg-dropped|ack-drop|ack-err)\b\s*[:=]\s*0\b",
                r"oldest-drop-log-time",
                r"drop-num",
                r"sqlfilter",
                r"handler name",
                r"rule name",
            ]),
            recommendation=(
                "Check device log connection, OFTP/514 paths, log rate, disk quota, "
                "FortiAnalyzer service state, and ingestion counters over time."
            ),
        ),

        Rule(
            rule_id="FAZ_INDEX_ANALYTICS_PIPELINE",
            severity="CRIT",
            category="FortiAnalyzer / Indexing",
            title="Log indexing, ClickHouse, analytics, or SIEM pipeline issue found",
            patterns=compile_patterns([
                r"\bsqllogd\b.*\b(?:failed|failure|error|timeout|crash|restart|stuck|blocked)\b",
                r"\bsiemdbd\b.*\b(?:failed|failure|error|timeout|crash|restart|stuck|blocked)\b",
                r"\bclickhouse\b.*\b(?:failed|failure|exception|timeout|corrupt|crash|restart|stuck|broken)\b",
                r"\bindex(?:ing)?\b.*\b(?:failed|failure|error|stuck|behind|corrupt|rebuild)\b",
                r"\banalytic\w*\b.*\b(?:failed|failure|error|stuck|timeout)\b",
                r"\bairflow\b.*\b(?:failed|failure|error|timeout|stuck|deadlock)\b",
            ]),
            negative_patterns=compile_patterns([
                r"\bLISTEN\b",
                r"\bESTABLISHED\b",
                r"\b0\s+failed\b",
                r"failed\s*[:=]\s*0\b",
                r"error\s*[:=]\s*0\b",
            ]),
            recommendation=(
                "Review indexing backlog, ClickHouse health, sqllogd/siemdbd logs, disk latency, "
                "and recent upgrade/migration status."
            ),
        ),

        Rule(
            rule_id="FAZ_REPORT_DATASET_FAILURE",
            severity="WARN",
            category="FortiAnalyzer / Reports",
            title="Report, chart, or dataset generation issue found",
            patterns=compile_patterns([
                r"\breport\b.*\b(?:failed|failure|error|timeout|aborted|stuck)\b",
                r"\bdataset\b.*\b(?:failed|failure|error|timeout|invalid)\b",
                r"\bchart\b.*\b(?:failed|failure|error|timeout|invalid)\b",
                r"\bscheduled report\b.*\b(?:failed|failure|error|timeout)\b",
            ]),
            negative_patterns=compile_patterns([
                r"failed\s*[:=]\s*0\b",
                r"error\s*[:=]\s*0\b",
                r"last report.*successful",
            ]),
            recommendation=(
                "Check report timeframe, dataset SQL, ADOM/log availability, report queue, "
                "and database/index health."
            ),
        ),

        Rule(
            rule_id="FAZ_LOG_QUOTA_ARCHIVE",
            severity="WARN",
            category="FortiAnalyzer / Log Storage",
            title="Log quota, archive, retention, or storage-management issue found",
            patterns=compile_patterns([
                r"\bquota\b.*\b(?:exceed|exceeded|full|reached|failed|error)\b",
                r"\barchive\b.*\b(?:failed|failure|error|timeout|cannot|corrupt)\b",
                r"\bretention\b.*\b(?:failed|failure|error|purge|delete)\b",
                r"\blog\b.*\b(?:purge|purged|delete|deleted)\b.*\b(?:failed|failure|error)\b",
            ]),
            recommendation=(
                "Review ADOM quota, retention policy, archive path, disk usage, and whether "
                "log deletion/purge jobs are stuck."
            ),
        ),

        Rule(
            rule_id="FORTIGUARD_FDS_CONNECTIVITY",
            severity="WARN",
            category="FortiGuard / FDS",
            title="FortiGuard/FDS connectivity or update issue found",
            patterns=compile_patterns([
                r"\bfortiguard\b.*\b(?:failed|failure|timeout|unreachable|cannot|error|denied)\b",
                r"\bfds\b.*\b(?:failed|failure|timeout|unreachable|cannot|error|denied|code\s*[:=]\s*(?:4\d\d|5\d\d))\b",
                r"\bupdate\b.*\b(?:failed|failure|timeout|cannot connect|connection refused)\b",
                r"\bservice unavailable\b.*\b(?:fortiguard|fds)\b",
            ]),
            negative_patterns=compile_patterns([
                r"fds_code\s*[:=]\s*200",
                r"license is valid",
                r"service.*on",
                r"\bfailed\s*[:=]\s*0\b",
            ]),
            recommendation=(
                "Check DNS, routing, proxy, FortiGuard ports, contract/licensing state, "
                "and update service status."
            ),
        ),

        Rule(
            rule_id="LICENSE_CERTIFICATE_EXPIRY",
            severity="WARN",
            category="License / Certificate",
            title="License, certificate, or contract issue found",
            patterns=compile_patterns([
                r"\blicen[sc]e\b.*\b(?:expired|invalid|failed|not valid|unlicensed|evaluation expired)\b",
                r"\bcontract\b.*\b(?:expired|invalid|not valid)\b",
                r"\bcertificate\b.*\b(?:expired|invalid|failed|verify failed|not trusted|mismatch)\b",
                r"\bssl\b.*\b(?:certificate|cert)\b.*\b(?:expired|invalid|verify failed|mismatch)\b",
            ]),
            negative_patterns=compile_patterns([
                r"license status\s*:\s*valid",
                r"VM license is valid",
                r"expires in\s*:\s*\d+\s+days",
            ]),
            recommendation=(
                "Verify license/contract status, VM entitlement, certificate chain, time/NTP, "
                "and FortiCare registration."
            ),
        ),

        Rule(
            rule_id="FMG_FAZ_HA_SYNC",
            severity="WARN",
            category="HA",
            title="FMG/FAZ HA synchronization or role-state issue found",
            patterns=compile_patterns([
                r"\bha\b.*\b(?:sync failed|sync failure|out.of.sync|not synchronized|unsync|checksum mismatch)\b",
                r"\bcluster\b.*\b(?:out.of.sync|sync failed|member down|peer down|role change|failover)\b",
                r"\bfabricsyncd\b.*\b(?:failed|failure|timeout|disconnect|out.of.sync|not synchronized)\b",
                r"\bheartbeat\b.*\b(?:lost|missed|timeout|failed)\b",
            ]),
            negative_patterns=compile_patterns([
                r"mode\s*:\s*standalone",
                r"ha mode\s*:\s*standalone",
                r"split-brain",
                r"split brain",
            ]),
            recommendation=(
                "Check HA mode, peer reachability, sync status, version/build match, storage health, "
                "and fabricsyncd logs."
            ),
        ),

        Rule(
            rule_id="BACKUP_RESTORE_IMPORT_EXPORT",
            severity="WARN",
            category="Backup / Restore",
            title="Backup, restore, import, or export issue found",
            patterns=compile_patterns([
                r"\bbackup\b.*\b(?:failed|failure|error|timeout|cannot|corrupt)\b",
                r"\brestore\b.*\b(?:failed|failure|error|timeout|cannot|corrupt)\b",
                r"\bimport\b.*\b(?:failed|failure|error|timeout|cannot|invalid)\b",
                r"\bexport\b.*\b(?:failed|failure|error|timeout|cannot)\b",
            ]),
            recommendation=(
                "Verify file integrity, destination reachability, disk space, permissions, "
                "build compatibility, and ADOM/database state."
            ),
        ),

        Rule(
            rule_id="UPGRADE_MIGRATION_FAILURE",
            severity="CRIT",
            category="Upgrade / Migration",
            title="Upgrade, migration, or database conversion issue found",
            patterns=compile_patterns([
                r"\bupgrade\b.*\b(?:failed|failure|error|aborted|rollback|cannot)\b",
                r"\bmigration\b.*\b(?:failed|failure|error|aborted|cannot)\b",
                r"\bdb\b.*\b(?:migration|convert|conversion)\b.*\b(?:failed|failure|error)\b",
                r"\bpost-upgrade\b.*\b(?:failed|failure|error)\b",
            ]),
            recommendation=(
                "Review upgrade path compatibility, migration logs, storage/memory health, "
                "and pre/post-upgrade checks."
            ),
        ),

        Rule(
            rule_id="NETWORK_ROUTE_DNS_CONNECTIVITY",
            severity="WARN",
            category="Network",
            title="Network, route, DNS, or connectivity issue found",
            patterns=compile_patterns([
                r"\bDNS\b.*\b(?:failed|failure|timeout|unreachable|cannot resolve|no response)\b",
                r"\bresolve\b.*\b(?:failed|failure|timeout|no such host)\b",
                r"\bconnection\b.*\b(?:refused|reset|timeout|timed out|unreachable)\b",
                r"\bno route to host\b",
                r"\bnetwork is unreachable\b",
                r"\bhost is unreachable\b",
            ]),
            negative_patterns=compile_patterns([
                r"\b0\s+errors\b",
                r"\b0\s+dropped\b",
                r"nic link is down",
                r"status:\s*down",
                r"no such device",
            ]),
            recommendation=(
                "Check route table, DNS servers, proxy settings, firewall rules, and peer/service reachability."
            ),
        ),

        Rule(
            rule_id="AUTH_ADMIN_FAILURE",
            severity="WARN",
            category="Authentication / Admin",
            title="Admin authentication or authorization issue found",
            patterns=compile_patterns([
                r"\bauthentication\b.*\b(?:failed|failure|denied|invalid)\b",
                r"\bauthori[sz]ation\b.*\b(?:failed|failure|denied|invalid)\b",
                r"\blogin\b.*\b(?:failed|failure|denied|invalid password)\b",
                r"\bpermission denied\b",
                r"\binsufficient privilege\b",
                r"\btacacs\b.*\b(?:failed|failure|timeout|denied)\b",
                r"\bradius\b.*\b(?:failed|failure|timeout|denied)\b",
                r"\bldap\b.*\b(?:failed|failure|timeout|denied|bind failed)\b",
                r"\bsaml\b.*\b(?:failed|failure|invalid|denied|assertion)\b",
            ]),
            negative_patterns=compile_patterns([
                r"\bfailed\s*[:=]\s*0\b",
                r"\berror\s*[:=]\s*0\b",
            ]),
            recommendation=(
                "Check admin profile, remote-auth settings, server reachability, time/NTP, "
                "certificates, and event timestamps."
            ),
        ),
    ]


# -----------------------------------------------------------------------------
# Analyzer
# -----------------------------------------------------------------------------

class TACAnalyzer:
    def __init__(self, context_lines: int = DEFAULT_CONTEXT_LINES):
        self.context_lines = context_lines
        self.rules = build_rules()

    def analyze(self, files: List[LogFile]) -> Tuple[List[Finding], List[Fact], Dict[str, object]]:
        findings: List[Finding] = []
        facts: List[Fact] = []

        for lf in files:
            lines = lf.text.splitlines()
            facts.extend(self._extract_facts(lf, lines))
            findings.extend(self._apply_rules(lf, lines))
            findings.extend(self._numeric_threshold_checks(lf, lines))

        findings.extend(SizingAnalyzer().analyze(facts))
        findings = self._dedupe_findings(findings)
        facts = self._dedupe_facts(facts)

        findings.sort(
            key=lambda f: (
                SEVERITY_RANK.get(f.severity, 99),
                f.category,
                f.title,
                f.evidence.file,
                f.evidence.line,
            )
        )

        summary = self._build_summary(files, findings, facts)
        return findings, facts, summary

    def _apply_rules(self, lf: LogFile, lines: List[str]) -> List[Finding]:
        out: List[Finding] = []
        per_rule_count: Counter[str] = Counter()

        for idx, line in enumerate(lines):
            if self._skip_line_global(line):
                continue

            for rule in self.rules:
                if per_rule_count[rule.rule_id] >= rule.max_findings:
                    continue

                if rule.negative_patterns and any(p.search(line) for p in rule.negative_patterns):
                    continue

                if not any(p.search(line) for p in rule.patterns):
                    continue

                if self._is_false_positive(rule.rule_id, line):
                    continue

                evidence = Evidence(
                    file=lf.path,
                    line=idx + 1,
                    text=truncate(line),
                    context=line_context(lines, idx, self.context_lines),
                )

                out.append(Finding(
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    source=lf.path,
                    evidence=evidence,
                    recommendation=rule.recommendation,
                    rule_id=rule.rule_id,
                ))

                per_rule_count[rule.rule_id] += 1

        return out

    def _skip_line_global(self, line: str) -> bool:
        low = line.strip().lower()

        if not low:
            return True

        if low.startswith("###"):
            return True

        if re.match(r"^\s*(set|unset|edit|next|end|config)\b", line, re.IGNORECASE):
            return True

        if "sqlfilter" in low or "handler name" in low or "rule name" in low:
            return True

        return False

    def _is_false_positive(self, rule_id: str, line: str) -> bool:
        low = line.lower()

        if re.search(r"\b(?:failed|failures?|errors?|dropped|drop|denied|timeout)\b\s*[:=]\s*0\b", low):
            return True

        if re.search(r"\b0\s+(?:failed|failures?|errors?|dropped|drops?)\b", low):
            return True

        if re.search(r"\b(?:listen|established|time_wait)\b", low):
            if not re.search(r"failed|failure|error|timeout|refused|reset|denied|crash|corrupt", low):
                return True

        if rule_id == "FMG_DEVICE_MANAGER_FGFM" and "fgfm ssl proxy" in low:
            return True

        if rule_id == "NETWORK_ROUTE_DNS_CONNECTIVITY" and re.search(
            r"\b(?:nic link is down|status:\s*down|no such device)\b",
            low,
        ):
            return True

        if rule_id == "DB_POSTGRES_CLICKHOUSE_REDIS" and re.search(
            r"\b(?:postgres|clickhouse|redis)\b.*\b(?:listen|established)\b",
            low,
        ):
            return True

        if rule_id == "CRASH_CORE_PANIC" and "show daemon thread backtrace" in low:
            return True

        return False

    def _numeric_threshold_checks(self, lf: LogFile, lines: List[str]) -> List[Finding]:
        out: List[Finding] = []
        section = ""

        for idx, line in enumerate(lines):
            stripped = line.strip()
            low = stripped.lower()

            if stripped.startswith("###"):
                section = stripped.lstrip("#").strip().lower()
                continue

            if stripped.lower().startswith("cpu:"):
                section = "cpu"
                continue

            if stripped.lower().startswith("memory:"):
                section = "memory"
                continue

            if stripped.lower().startswith("hard disk:"):
                section = "hard disk"
                continue

            if stripped.lower().startswith("flash disk:"):
                section = "flash disk"
                continue

            if section == "cpu" and re.search(r"\bUsed\b", line, re.IGNORECASE):
                pct = self._first_percent(line)
                if pct is not None and "idle" not in low:
                    out.extend(self._threshold_from_percent("CPU", pct, lf, lines, idx, "THRESHOLD_CPU_HIGH"))

            if section == "memory" and re.search(r"\bUsed\b", line, re.IGNORECASE):
                pct = self._first_percent(line)
                if pct is not None:
                    out.extend(self._threshold_from_percent("Memory", pct, lf, lines, idx, "THRESHOLD_MEMORY_HIGH"))

            if section in {"hard disk", "flash disk"} and re.search(r"\bUsed\b", line, re.IGNORECASE):
                pct = self._first_percent(line)
                if pct is not None:
                    out.extend(
                        self._threshold_from_percent(
                            "Disk / Filesystem",
                            pct,
                            lf,
                            lines,
                            idx,
                            "THRESHOLD_DISK_HIGH",
                        )
                    )

            disk_pct = self._extract_disk_use_percent(line)
            if disk_pct is not None:
                out.extend(
                    self._threshold_from_percent(
                        "Disk / Filesystem",
                        disk_pct,
                        lf,
                        lines,
                        idx,
                        "THRESHOLD_DISK_HIGH",
                    )
                )

            m_idle = re.search(
                r"(?:cpu\(s\)|cpu).*?(\d+(?:\.\d+)?)\s*%?\s*(?:id|idle)\b",
                line,
                re.IGNORECASE,
            )
            if m_idle:
                used = 100.0 - float(m_idle.group(1))
                out.extend(
                    self._threshold_from_percent(
                        "CPU",
                        used,
                        lf,
                        lines,
                        idx,
                        "THRESHOLD_CPU_IDLE_HIGH",
                        title_suffix="from idle value",
                    )
                )

            counter_name = (
                r"errors?|dropped|drops?|failures?|failed|denied|retrans(?:mits)?|"
                r"discard(?:ed)?|collisions|overruns|frame|carrier|ack-err|ack-drop|msg-dropped|"
                r"rcv_oversize|parse_msg|build_resp|invalid_access_token|redis-err|socket"
            )

            counter_values: List[Tuple[str, int]] = []

            for m in re.finditer(rf"\b({counter_name})\b\s*[:=]\s*(\d+)\b", line, re.IGNORECASE):
                counter_values.append((m.group(1), int(m.group(2))))

            positive = [(name, value) for name, value in counter_values if value > 0]

            if positive and not re.search(r"oldest-drop-log-time|drop-num|sqlfilter|handler name|rule name", low):
                name, value = max(positive, key=lambda item: item[1])
                severity = "WARN" if value >= 100 else "INFO"
                title = (
                    f"High non-zero {name} counter observed ({value})"
                    if value >= 100
                    else f"Non-zero {name} counter observed ({value})"
                )

                out.append(self._make_threshold_finding(
                    severity=severity,
                    category="Counters",
                    title=title,
                    lf=lf,
                    lines=lines,
                    idx=idx,
                    rule_id="COUNTER_NONZERO",
                    recommendation=(
                        "Correlate the counter with service/interface context and compare against "
                        "a later sample to confirm it is increasing."
                    ),
                ))

        return out

    def _threshold_from_percent(
        self,
        category: str,
        pct: float,
        lf: LogFile,
        lines: List[str],
        idx: int,
        rule_id: str,
        title_suffix: str = "",
    ) -> List[Finding]:
        if pct >= 95:
            severity = "CRIT"
        elif pct >= 85:
            severity = "WARN"
        else:
            return []

        label = category.split("/")[0].strip()
        suffix = f" {title_suffix}" if title_suffix else ""
        title = f"High {label.lower()} usage detected{suffix} ({pct:.1f}%)"

        recommendation = {
            "CPU": "Check top CPU processes, scheduled reports, log/indexing spikes, and whether high CPU is sustained.",
            "Memory": "Check process memory, swap usage, report/indexing workload, and VM sizing.",
            "Disk / Filesystem": "Review df/df -i, log/database retention, archive usage, old reports/backups, and storage health.",
        }.get(category, "Review this resource threshold and correlate with timestamps/user impact.")

        return [
            self._make_threshold_finding(
                severity,
                category,
                title,
                lf,
                lines,
                idx,
                rule_id,
                recommendation,
            )
        ]

    def _make_threshold_finding(
        self,
        severity: str,
        category: str,
        title: str,
        lf: LogFile,
        lines: List[str],
        idx: int,
        rule_id: str,
        recommendation: str,
    ) -> Finding:
        return Finding(
            severity=severity,
            category=category,
            title=title,
            source=lf.path,
            evidence=Evidence(
                file=lf.path,
                line=idx + 1,
                text=truncate(lines[idx]),
                context=line_context(lines, idx, self.context_lines),
            ),
            recommendation=recommendation,
            rule_id=rule_id,
        )

    def _first_percent(self, line: str) -> Optional[float]:
        m = re.search(r"(\d{1,3}(?:\.\d+)?)\s*%", line)
        if not m:
            return None

        value = float(m.group(1))
        if 0 <= value <= 100:
            return value

        return None

    def _extract_disk_use_percent(self, line: str) -> Optional[float]:
        if "%" not in line:
            return None

        low = line.lower()

        likely_df = (
            re.search(r"\bfilesystem\b|\b/dev/|\btmpfs\b|\bdevtmpfs\b|\bmapper\b|\brootfs\b", low)
            or re.search(r"\s/[\w/.-]*\s*$", line)
        )

        if not likely_df:
            return None

        values = [float(x) for x in re.findall(r"\b(\d{1,3})%\b", line)]
        values = [x for x in values if 0 <= x <= 100]

        return max(values) if values else None

    def _extract_facts(self, lf: LogFile, lines: List[str]) -> List[Fact]:
        facts: List[Fact] = []
        processor_ids = set()
        section = ""

        def add(name: str, value: str, line_no: int) -> None:
            value = truncate(value.strip(), 180)
            if value:
                facts.append(Fact(name=name, value=value, source=lf.path, line=line_no))

        for idx, raw in enumerate(lines):
            line_no = idx + 1
            line = raw.strip()
            low = line.lower()

            if line.startswith("###"):
                section = line.lstrip("#").strip().lower()
                continue

            if not line:
                continue

            for name, regex in [
                ("platform_type", r"^Platform Type\s*:\s*(.+)$"),
                ("platform_full_name", r"^Platform Full Name\s*:\s*(.+)$"),
                ("version", r"^Version\s*:\s*(.+)$"),
                ("serial", r"^Serial Number\s*:\s*(.+)$"),
                ("hostname", r"^Hostname\s*:\s*(.+)$"),
                ("ha_mode", r"^HA Mode\s*:\s*(.+)$"),
                ("license_status", r"^License Status\s*:\s*(.+)$"),
                ("adom_config", r"^Admin Domain Configuration\s*:\s*(.+)$"),
                ("max_adoms", r"^Max Number of Admin Domains\s*:\s*(\d+)"),
                ("gb_per_day", r"^(?:GB/day|Licensed GB/Day)\s*:\s*(.+)$"),
                ("max_devices", r"^Max devices\s*:\s*(\d+)"),
            ]:
                m = re.search(regex, line, re.IGNORECASE)
                if m:
                    add(name, m.group(1), line_no)

            m = re.search(r"\b(FMG|FAZ|FL)-?VM64.*?build(\d+)", line, re.IGNORECASE)
            if m:
                add("image_build", line, line_no)

            m = re.search(r"^processor\s*:\s*(\d+)\b", line, re.IGNORECASE)
            if m:
                processor_ids.add(int(m.group(1)))

            m = re.search(r"^MemTotal:\s*(\d+)\s*kB", line, re.IGNORECASE)
            if m:
                kb = int(m.group(1))
                add("ram_gb", f"{kb / 1024 / 1024:.1f}", line_no)

            m = re.search(r"^Total(?:\s*\(Excluding Swap\))?:\s*([\d,]+)\s*KB", line, re.IGNORECASE)
            if m and "memory" in section:
                kb = int(m.group(1).replace(",", ""))
                add("ram_gb", f"{kb / 1024 / 1024:.1f}", line_no)

            m = re.search(
                r"^Disk Usage\s*:\s*Free\s+([\d.]+)GB,\s*Total\s+([\d.]+)GB",
                line,
                re.IGNORECASE,
            )
            if m:
                add("disk_free_gb", m.group(1), line_no)
                add("disk_total_gb", m.group(2), line_no)

            m = re.search(r"^Total:\s*([\d,]+)\s*KB", line, re.IGNORECASE)
            if m and "hard disk" in section:
                kb = int(m.group(1).replace(",", ""))
                add("disk_total_gb", f"{kb / 1024 / 1024:.1f}", line_no)

            for regex in [
                r"\bManaged Devices\s*:\s*(\d+)\b",
                r"\bNumber of managed devices\s*:\s*(\d+)\b",
                r"\bTotal managed devices\s*:\s*(\d+)\b",
                r"\bmanaged-devices\s*[:=]\s*(\d+)\b",
                r"\bnum-devices\s*[:=]\s*(\d+)\b",
                r"\bdevices\s*[:=]\s*(\d+)\b",
            ]:
                m = re.search(regex, line, re.IGNORECASE)
                if m and not re.search(r"packets|bytes|errors|dropped|max devices", low):
                    add("managed_devices", m.group(1), line_no)

        if processor_ids:
            add("cpu_cores", str(len(processor_ids)), 1)

        combined = "\n".join(lines[:300]).lower() + " " + lf.path.lower()

        if "fortianalyzer" in combined or re.search(r"\bfaz\b|fazvm", combined):
            add("product", "FortiAnalyzer", 1)

        if "fortimanager" in combined or re.search(r"\bfmg\b|fmgvm", combined):
            add("product", "FortiManager", 1)

        return facts

    def _dedupe_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        out: List[Finding] = []

        for item in findings:
            key = (item.rule_id, item.evidence.file, item.evidence.line, item.evidence.text)
            if key in seen:
                continue

            seen.add(key)
            out.append(item)

        return out

    def _dedupe_facts(self, facts: List[Fact]) -> List[Fact]:
        seen = set()
        out: List[Fact] = []

        for fact in facts:
            key = (fact.name, fact.value, fact.source, fact.line)
            if key in seen:
                continue

            seen.add(key)
            out.append(fact)

        return out

    def _build_summary(
        self,
        files: List[LogFile],
        findings: List[Finding],
        facts: List[Fact],
    ) -> Dict[str, object]:
        severity_counts = Counter(f.severity for f in findings)
        category_counts = Counter(f.category for f in findings)
        rule_counts = Counter(f.rule_id for f in findings)
        file_counts = Counter(f.evidence.file for f in findings)
        product = detect_product(facts)

        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "product": product,
            "files_analyzed": len(files),
            "total_text_bytes": sum(f.size_bytes for f in files),
            "findings_total": len(findings),
            "critical": severity_counts.get("CRIT", 0),
            "warnings": severity_counts.get("WARN", 0),
            "info": severity_counts.get("INFO", 0),
            "category_counts": dict(category_counts),
            "rule_counts": dict(rule_counts),
            "top_files": file_counts.most_common(10),
        }


# -----------------------------------------------------------------------------
# Sizing analyzer
# -----------------------------------------------------------------------------

class SizingAnalyzer:
    """
    Basic FortiManager sizing heuristic.

    FortiAnalyzer sizing is not calculated from managed-device count because FAZ sizing depends
    heavily on GB/day, peak/sustained log rate, retention, analytics, reports, ADOM count,
    and disk I/O.
    """

    FMG_TIERS = [
        (100, 2, 8, 200),
        (500, 6, 32, 500),
        (1000, 8, 64, 1000),
        (5000, 16, 128, 2000),
        (10000, 32, 256, 4000),
    ]

    def analyze(self, facts: List[Fact]) -> List[Finding]:
        product = detect_product(facts)
        out: List[Finding] = []

        if product == "FortiAnalyzer":
            out.append(self._info(
                "FAZ_SIZING_NOTE",
                "FortiAnalyzer sizing requires log-rate/retention workload review",
                "Detected FortiAnalyzer. Device-count-only FMG sizing is intentionally not applied to FAZ.",
                "For FAZ, validate GB/day, peak/sustained log rate, retention, analytics, reports, ADOM count, and disk I/O.",
            ))
            return out

        if product != "FortiManager":
            return out

        managed_devices = self._max_int_fact(facts, "managed_devices")
        cpu_cores = self._max_float_fact(facts, "cpu_cores")
        ram_gb = self._max_float_fact(facts, "ram_gb")
        disk_gb = self._max_float_fact(facts, "disk_total_gb")

        if managed_devices is None:
            return out

        req_cpu, req_ram, req_disk = self._required_fmg(managed_devices)

        out.append(self._info(
            "FMG_SIZING_REQUIREMENT",
            f"FMG sizing requirement estimated for {managed_devices} managed devices",
            f"Estimated required tier: {req_cpu} CPU / {req_ram} GB RAM / {req_disk} GB disk",
            "Compare with the official sizing guide for the exact firmware/build and enabled features.",
        ))

        checks = [
            ("CPU", cpu_cores, req_cpu, "cpu_cores"),
            ("RAM", ram_gb, req_ram, "ram_gb"),
            ("Disk", disk_gb, req_disk, "disk_total_gb"),
        ]

        for label, actual, required, fact_name in checks:
            if actual is None:
                continue

            if actual + 0.01 < required:
                out.append(self._crit(
                    f"FMG_SIZING_{label.upper()}_LOW",
                    f"FMG {label} below estimated requirement",
                    f"Detected {label}: {actual:g}; estimated required: {required:g}",
                    f"Increase {label} or reduce managed-device/workload demand after validating against the official sizing guide.",
                    source_fact=self._first_fact(facts, fact_name),
                ))
            else:
                out.append(self._info(
                    f"FMG_SIZING_{label.upper()}_OK",
                    f"FMG {label} meets estimated requirement",
                    f"Detected {label}: {actual:g}; estimated required: {required:g}",
                    "No sizing issue detected for this resource using the built-in heuristic.",
                    source_fact=self._first_fact(facts, fact_name),
                ))

        return out

    def _required_fmg(self, devices: int) -> Tuple[int, int, int]:
        for limit, cpu, ram, disk in self.FMG_TIERS:
            if devices <= limit:
                return cpu, ram, disk

        return 32, 256, 4000

    def _max_int_fact(self, facts: List[Fact], name: str) -> Optional[int]:
        values = []

        for f in facts:
            if f.name != name:
                continue

            try:
                values.append(int(float(f.value)))
            except ValueError:
                pass

        return max(values) if values else None

    def _max_float_fact(self, facts: List[Fact], name: str) -> Optional[float]:
        values = []

        for f in facts:
            if f.name != name:
                continue

            try:
                values.append(float(f.value))
            except ValueError:
                pass

        return max(values) if values else None

    def _first_fact(self, facts: List[Fact], name: str) -> Optional[Fact]:
        for f in facts:
            if f.name == name:
                return f

        return None

    def _info(
        self,
        rule_id: str,
        title: str,
        text: str,
        recommendation: str,
        source_fact: Optional[Fact] = None,
    ) -> Finding:
        return self._finding("INFO", rule_id, title, text, recommendation, source_fact)

    def _crit(
        self,
        rule_id: str,
        title: str,
        text: str,
        recommendation: str,
        source_fact: Optional[Fact] = None,
    ) -> Finding:
        return self._finding("CRIT", rule_id, title, text, recommendation, source_fact)

    def _finding(
        self,
        severity: str,
        rule_id: str,
        title: str,
        text: str,
        recommendation: str,
        source_fact: Optional[Fact],
    ) -> Finding:
        if source_fact:
            ev = Evidence(
                source_fact.source,
                source_fact.line,
                text,
                [f"{source_fact.line}: {source_fact.name}={source_fact.value}"],
            )
            source = source_fact.source
        else:
            ev = Evidence("derived", 0, text, [])
            source = "derived"

        return Finding(
            severity=severity,
            category="Sizing",
            title=title,
            source=source,
            evidence=ev,
            recommendation=recommendation,
            rule_id=rule_id,
        )


def detect_product(facts: List[Fact]) -> str:
    values = " ".join(
        f.value for f in facts
        if f.name in {"product", "platform_type", "platform_full_name", "version", "image_build"}
    ).lower()

    if "fortianalyzer" in values or "faz" in values:
        return "FortiAnalyzer"

    if "fortimanager" in values or "fmg" in values:
        return "FortiManager"

    return "Unknown"


# -----------------------------------------------------------------------------
# Output builders
# -----------------------------------------------------------------------------

def write_consolidated(files: List[LogFile], output_path: Path) -> None:
    ensure_dir(output_path.parent)

    with output_path.open("w", encoding="utf-8", errors="replace") as fh:
        for lf in files:
            fh.write(f"### {lf.name}\n")
            fh.write(lf.text.rstrip("\n"))
            fh.write("\n\n")


def fact_to_dict(fact: Fact) -> Dict[str, object]:
    return dataclasses.asdict(fact)


def finding_to_dict(finding: Finding) -> Dict[str, object]:
    return dataclasses.asdict(finding)


def build_json_payload(
    input_path: Path,
    summary: Dict[str, object],
    facts: List[Fact],
    findings: List[Finding],
    skipped: List[Dict[str, str]],
    consolidated_path: Optional[Path],
) -> Dict[str, object]:
    return {
        "input": str(input_path),
        "summary": summary,
        "facts": [fact_to_dict(f) for f in facts],
        "findings": [finding_to_dict(f) for f in findings],
        "skipped": skipped,
        "consolidated_path": str(consolidated_path) if consolidated_path else None,
    }


def build_text_report(
    input_path: Path,
    summary: Dict[str, object],
    facts: List[Fact],
    findings: List[Finding],
    skipped: List[Dict[str, str]],
    consolidated_path: Optional[Path],
    max_evidence_per_section: int = 200,
) -> str:
    fh = io.StringIO()

    fh.write("=" * 78 + "\n")
    fh.write("FMG/FAZ TAC REPORT ANALYSIS\n")
    fh.write("=" * 78 + "\n")
    fh.write(f"Generated       : {summary.get('generated_at')}\n")
    fh.write(f"Input           : {input_path}\n")
    fh.write(f"Detected product: {summary.get('product')}\n")
    fh.write(f"Files analyzed  : {summary.get('files_analyzed')}\n")
    fh.write(f"Text bytes read : {summary.get('total_text_bytes')}\n")

    if consolidated_path:
        fh.write(f"Consolidated    : {consolidated_path}\n")

    fh.write("\n")

    fh.write("=" * 78 + "\n")
    fh.write("SUMMARY\n")
    fh.write("=" * 78 + "\n")
    fh.write(f"[CRIT] Critical findings : {summary.get('critical')}\n")
    fh.write(f"[WARN] Warnings          : {summary.get('warnings')}\n")
    fh.write(f"[INFO] Info findings     : {summary.get('info')}\n")
    fh.write(f"[TOTAL] Findings         : {summary.get('findings_total')}\n")
    fh.write("\n")

    category_counts = summary.get("category_counts") or {}

    if category_counts:
        fh.write("Findings by category:\n")
        for category, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0])):
            fh.write(f"  - {category}: {count}\n")
        fh.write("\n")

    top_files = summary.get("top_files") or []

    if top_files:
        fh.write("Top files by finding count:\n")
        for src, count in top_files:
            fh.write(f"  - {count:>4}  {src}\n")
        fh.write("\n")

    fh.write("=" * 78 + "\n")
    fh.write("DISCOVERED FACTS\n")
    fh.write("=" * 78 + "\n")

    if facts:
        grouped: Dict[str, List[Fact]] = defaultdict(list)

        for fact in facts:
            grouped[fact.name].append(fact)

        for name in sorted(grouped):
            values = grouped[name][:10]
            rendered = "; ".join(
                f"{f.value} ({Path(f.source).name}:{f.line})"
                for f in values
            )
            fh.write(f"{name:<20}: {rendered}\n")
    else:
        fh.write("No common system facts were detected.\n")

    fh.write("\n")

    fh.write("=" * 78 + "\n")
    fh.write("FINDINGS\n")
    fh.write("=" * 78 + "\n")

    if not findings:
        fh.write("No critical/warning/info rule matches were found in readable TAC text.\n")
    else:
        for idx, finding in enumerate(findings[:max_evidence_per_section], 1):
            icon = SEVERITY_ICON.get(finding.severity, f"[{finding.severity}]")
            fh.write(f"\n{idx}. {icon} {finding.category} - {finding.title}\n")
            fh.write(f"   Rule          : {finding.rule_id}\n")
            fh.write(f"   Source        : {finding.evidence.file}:{finding.evidence.line}\n")
            fh.write(f"   Evidence      : {finding.evidence.text}\n")

            if finding.evidence.context:
                fh.write("   Context       :\n")
                for ctx in finding.evidence.context:
                    fh.write(f"      {ctx}\n")

            fh.write(f"   Recommendation: {finding.recommendation}\n")

        if len(findings) > max_evidence_per_section:
            remaining = len(findings) - max_evidence_per_section
            fh.write(
                f"\n... {remaining} additional findings omitted. "
                f"Increase --max-text-findings to show more.\n"
            )

    fh.write("\n")

    fh.write("=" * 78 + "\n")
    fh.write("SKIPPED FILES\n")
    fh.write("=" * 78 + "\n")

    if skipped:
        for item in skipped[:200]:
            fh.write(f"- {item.get('path')}: {item.get('reason')}\n")

        if len(skipped) > 200:
            fh.write(f"... {len(skipped) - 200} additional skipped files omitted.\n")
    else:
        fh.write("None\n")

    return fh.getvalue()


def write_text_report(
    output_path: Path,
    input_path: Path,
    summary: Dict[str, object],
    facts: List[Fact],
    findings: List[Finding],
    skipped: List[Dict[str, str]],
    consolidated_path: Optional[Path],
    max_evidence_per_section: int,
) -> None:
    ensure_dir(output_path.parent)

    output_path.write_text(
        build_text_report(
            input_path,
            summary,
            facts,
            findings,
            skipped,
            consolidated_path,
            max_evidence_per_section,
        ),
        encoding="utf-8",
        errors="replace",
    )


def write_json_report(
    output_path: Path,
    input_path: Path,
    summary: Dict[str, object],
    facts: List[Fact],
    findings: List[Finding],
    skipped: List[Dict[str, str]],
    consolidated_path: Optional[Path],
) -> None:
    ensure_dir(output_path.parent)

    payload = build_json_payload(
        input_path,
        summary,
        facts,
        findings,
        skipped,
        consolidated_path,
    )

    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
        errors="replace",
    )


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze FortiManager/FortiAnalyzer TAC reports. Default output is TXT printed to terminal.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "input",
        help="TAC archive, extracted folder, .log, or consolidated .txt report",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default="tac_analysis_output",
        help="Output directory used only with --save-output or --save-consolidated",
    )

    parser.add_argument(
        "--save-output",
        action="store_true",
        help="Save TXT and JSON reports to --output-dir",
    )

    parser.add_argument(
        "--save-consolidated",
        action="store_true",
        help="Save consolidated TAC text to --output-dir",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to terminal instead of TXT",
    )

    parser.add_argument(
        "--context",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help="Evidence context lines before/after match",
    )

    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=DEFAULT_MAX_FILE_MB,
        help="Maximum single file size to read",
    )

    parser.add_argument(
        "--max-total-mb",
        type=int,
        default=DEFAULT_MAX_TOTAL_MB,
        help="Maximum total text size to read",
    )

    parser.add_argument(
        "--max-text-findings",
        type=int,
        default=200,
        help="Maximum findings shown in terminal TXT output",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr",
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    input_path = Path(args.input).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    stamp = now_stamp()

    consolidated_path = output_dir / f"TAC_Consolidated_{stamp}.txt" if args.save_consolidated else None
    txt_report_path = output_dir / f"TAC_Analysis_{stamp}.txt"
    json_report_path = output_dir / f"TAC_Analysis_{stamp}.json"

    try:
        if args.verbose:
            print(f"[INFO] Loading input: {input_path}", file=sys.stderr)

        loader = TACLoader(
            max_file_mb=args.max_file_mb,
            max_total_mb=args.max_total_mb,
        )

        files = loader.load(input_path)

        if not files:
            print("[ERROR] No readable text files were found in the input.", file=sys.stderr)

            if loader.skipped:
                print("[INFO] Skipped files:", file=sys.stderr)
                for item in loader.skipped[:20]:
                    print(f"  - {item.get('path')}: {item.get('reason')}", file=sys.stderr)

            return 2

        if args.verbose:
            print(f"[INFO] Read {len(files)} unique readable text files", file=sys.stderr)

        if consolidated_path:
            write_consolidated(files, consolidated_path)

            if args.verbose:
                print(f"[INFO] Saved consolidated TAC text: {consolidated_path}", file=sys.stderr)

        analyzer = TACAnalyzer(context_lines=args.context)
        findings, facts, summary = analyzer.analyze(files)

        if args.save_output:
            write_text_report(
                txt_report_path,
                input_path,
                summary,
                facts,
                findings,
                loader.skipped,
                consolidated_path,
                args.max_text_findings,
            )

            write_json_report(
                json_report_path,
                input_path,
                summary,
                facts,
                findings,
                loader.skipped,
                consolidated_path,
            )

        if args.json:
            payload = build_json_payload(
                input_path,
                summary,
                facts,
                findings,
                loader.skipped,
                consolidated_path,
            )
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(
                build_text_report(
                    input_path,
                    summary,
                    facts,
                    findings,
                    loader.skipped,
                    consolidated_path,
                    max_evidence_per_section=args.max_text_findings,
                ),
                end="",
            )

        if args.save_output:
            print("\n" + "=" * 78)
            print(f"Saved TXT report : {txt_report_path}")
            print(f"Saved JSON report: {json_report_path}")

        if consolidated_path:
            print(f"Saved consolidated: {consolidated_path}")

        return 0

    except KeyboardInterrupt:
        print("\n[ERROR] Interrupted by user.", file=sys.stderr)
        return 130

    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)

        if args.verbose:
            raise

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
