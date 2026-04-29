# Please do not change anything if you don't know what you're doing.
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from pathlib import PurePosixPath
from typing import Iterable


VERSION = "0.5.0"
SEVERITY_SCORE = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}
MAX_TEXT_SCAN_BYTES = 1_000_000
ENTROPY_SAMPLE_CHUNK_BYTES = 128 * 1024
MAX_ARCHIVE_ENTRIES = 1_000
MAX_ARCHIVE_CONTENT_CANDIDATES = 200
MAX_ARCHIVE_TEXT_ENTRY_BYTES = 300_000
MAX_ARCHIVE_FINDINGS = 80
MAX_ENTROPY_WINDOWS = 16
DEFAULT_EXCLUDED_DIRS = {"reports", "quarantine", "__pycache__", ".git", ".venv", "venv"}
COLOR_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
COLORS = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
}

BUILTIN_KNOWN_BAD_SHA256 = {
    "7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab",
}

BUILTIN_KNOWN_BAD_DETAILS = {
    "7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab": "lnstaIer.exe known-bad sample",
}

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".msi",
    ".jar",
    ".lnk",
    ".url",
    ".reg",
    ".cpl",
    ".ocx",
    ".sys",
    ".chm",
    ".xll",
    ".iso",
    ".img",
}

SIGNED_APP_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".cpl", ".ocx", ".sys"}
PE_LIKE_EXTENSIONS = SIGNED_APP_EXTENSIONS | {".com"}
ZIP_CONTAINER_EXTENSIONS = {
    ".zip",
    ".jar",
    ".apk",
    ".xpi",
    ".crx",
    ".vsix",
    ".nupkg",
    ".docx",
    ".docm",
    ".dotm",
    ".xlsx",
    ".xlsm",
    ".xlam",
    ".pptx",
    ".pptm",
    ".ppam",
}
ARCHIVE_EXTENSIONS = ZIP_CONTAINER_EXTENSIONS
UNSUPPORTED_ARCHIVE_EXTENSIONS = {".7z", ".rar", ".cab", ".iso", ".img"}
MACRO_DOCUMENT_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xlam", ".pptm", ".ppam"}
ARCHIVE_HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".wsf",
    ".hta",
    ".msi",
    ".lnk",
    ".cpl",
    ".ocx",
    ".sys",
    ".chm",
    ".xll",
}
TEXT_CONTENT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".html",
    ".htm",
    ".url",
    ".reg",
    ".sh",
    ".bash",
    ".zsh",
}
SOURCE_CODE_EXTENSIONS = {".py", ".pyw", ".rb", ".php", ".pl", ".lua", ".go", ".java", ".cs", ".ts", ".tsx", ".jsx"}
DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".rtf",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".mp4",
    ".mp3",
    ".zip",
    ".rar",
    ".7z",
    ".cab",
    ".iso",
    ".img",
}
EXPECTED_FILE_TYPES_BY_EXTENSION = {
    ".pdf": {"pdf-document"},
    ".zip": {"zip-container"},
    ".jar": {"zip-container"},
    ".apk": {"zip-container"},
    ".docx": {"zip-container"},
    ".docm": {"zip-container"},
    ".xlsx": {"zip-container"},
    ".xlsm": {"zip-container"},
    ".pptx": {"zip-container"},
    ".pptm": {"zip-container"},
    ".png": {"png-image"},
    ".jpg": {"jpeg-image"},
    ".jpeg": {"jpeg-image"},
    ".gif": {"gif-image"},
    ".msi": {"compound-document"},
    ".rar": {"rar-archive"},
    ".7z": {"7z-archive"},
}


@dataclass(frozen=True)
class ContentRule:
    rule_id: str
    title: str
    severity: str
    regex: re.Pattern[bytes]
    remediation: str = "Review the matched script behavior and verify the file source before running it."


class RuleSet:
    def __init__(self, rules: Iterable[ContentRule | tuple[str, str, str, re.Pattern[bytes]] | tuple[str, str, str, re.Pattern[bytes], str]]) -> None:
        self.rules: list[ContentRule] = []
        for rule in rules:
            if isinstance(rule, ContentRule):
                self.rules.append(rule)
                continue
            if len(rule) == 4:
                rule_id, title, severity, regex = rule
                remediation = "Review the matched script behavior and verify the file source before running it."
            else:
                rule_id, title, severity, regex, remediation = rule
            self.rules.append(ContentRule(rule_id, title, severity, regex, remediation))

    def __iter__(self) -> Iterable[ContentRule]:
        return iter(self.rules)

    def extend(self, rules: Iterable[ContentRule]) -> None:
        self.rules.extend(rules)

SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"(?i)\bmr\s*beast\b|\bmrbeast\b"),
    re.compile(r"(?i)\bfree\s+(robux|vbucks|nitro|crypto|gift\s+card)\b"),
    re.compile(r"(?i)\bclaim\s+now\b|\bgiveaway\b|\bairdrop\b"),
    re.compile(r"(?i)\bcrack(ed)?\b|\bkeygen\b|\bactivator\b|\bcheat\b|\bexecutor\b"),
    re.compile(r"(?i)\bsetup\b.*\b(password|wallet|discord|nitro|robux|giveaway)\b"),
    re.compile(r"(?i)\blnstai?er\b"),
]

CONTENT_RULES = RuleSet([
    ("ps-encoded-command", "PowerShell encoded command", "high", re.compile(rb"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.{0,250}(?<!\w)(?:-enc|-encodedcommand)(?!\w)")),
    ("ps-download-exec", "PowerShell download and execute behavior", "high", re.compile(rb"(?is)\b(?:iex|invoke-expression)\b.{0,200}\b(?:downloadstring|downloadfile|webclient)\b")),
    ("ps-amsi-bypass", "PowerShell AMSI bypass indicators", "high", re.compile(rb"(?is)\b(?:amsiutils|amsiscanbuffer|amsiinitfailed|system\.management\.automation\.amsi)\b")),
    ("defender-tampering", "Microsoft Defender tampering command", "high", re.compile(rb"(?is)\b(?:Set-MpPreference|Add-MpPreference)\b.{0,250}\b(?:DisableRealtimeMonitoring|DisableIOAVProtection|ExclusionPath|ExclusionProcess)\b")),
    ("certutil-download", "certutil download behavior", "high", re.compile(rb"(?is)\bcertutil(?:\.exe)?\b.{0,220}\b(?:-urlcache|-split|-f)\b.{0,220}\bhttps?://")),
    ("bitsadmin-download", "BITSAdmin download behavior", "high", re.compile(rb"(?is)\bbitsadmin(?:\.exe)?\b.{0,220}\b(?:/transfer|/create|/addfile|http://|https://)\b")),
    ("mshta-remote-script", "MSHTA remote script execution", "high", re.compile(rb"(?is)\bmshta(?:\.exe)?\b.{0,220}\b(?:http://|https://|javascript:|vbscript:)")),
    ("rundll32-script", "rundll32 script execution", "high", re.compile(rb"(?is)\brundll32(?:\.exe)?\b.{0,220}\b(?:javascript:|mshtml|url\.dll|shell32\.dll)")),
    ("curl-pipe-shell", "Download piped into shell", "high", re.compile(rb"(?is)\b(?:curl|wget)\b.{0,300}\|\s*(?:sh|bash|powershell|pwsh|cmd)\b")),
    ("wscript-shell-run", "Windows Script Host process launch", "medium", re.compile(rb"(?is)\bwscript\.shell\b.{0,300}\b(?:run|exec)\b")),
    ("scheduled-task-persistence", "Scheduled task persistence command", "high", re.compile(rb"(?is)\bschtasks(?:\.exe)?\b.{0,220}\b/(?:create|change)\b")),
    ("registry-run-persistence", "Registry Run key persistence command", "high", re.compile(rb"(?is)\breg(?:\.exe)?\b.{0,120}\badd\b.{0,220}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b")),
    ("discord-token-theft", "Discord token harvesting indicators", "high", re.compile(rb"(?is)(?:discord(?:canary|ptb)?[\\/]+Local Storage[\\/]+leveldb|token.{0,80}discord(?:app)?\.com/api|leveldb.{0,120}(?:discord|token))")),
    ("browser-credential-access", "Browser credential store access", "high", re.compile(rb"(?is)(?:Login Data|Local State|Cookies).{0,250}(?:Chrome|Edge|Brave|Opera|Chromium|sqlite)|(?:Chrome|Edge|Brave|Opera|Chromium).{0,250}(?:Login Data|Cookies)")),
    ("crypto-wallet-access", "Crypto wallet file access", "high", re.compile(rb"(?is)(?:wallet\.dat|seed phrase|mnemonic).{0,160}(?:open|read|copy|upload|send|post|http|webhook|steal|grab|exfil)|(?:metamask|exodus|electrum|phantom).{0,160}(?:Local Extension Settings|IndexedDB|wallet|seed|mnemonic|upload|webhook|steal|grab|exfil)")),
    ("webhook-exfiltration", "Webhook exfiltration endpoint", "high", re.compile(rb"(?is)(?:discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}/send(?:Document|Message)|webhook).{0,250}(?:token|password|wallet|cookie|file|upload|exfil|grab|steal)")),
    ("fake-giveaway-language", "Scam giveaway language", "medium", re.compile(rb"(?is)(?:mr\s*beast|mrbeast|giveaway|free\s+(?:robux|crypto|gift\s*card|vbucks)|claim\s+now).{0,250}(?:login|wallet|verify|download|password|seed)")),
    ("suspicious-obfuscation", "Script obfuscation indicators", "medium", re.compile(rb"(?is)(?:fromcharcode|atob\(|base64decode|replace\(.{0,60}split\(|\[[\"']char[\"']\])")),
    ("long-base64-blob", "Long base64-like blob in script", "medium", re.compile(rb"(?s)\b[A-Za-z0-9+/]{220,}={0,2}\b")),
    ("pyinstaller-artifact", "Compiled Python executable artifact", "medium", re.compile(rb"(?is)(?:_MEI\d{5,}|PYZ-00\.pyz|pydata|pyimod|pyinstaller)")),
    ("nuitka-artifact", "Nuitka compiled Python artifact", "medium", re.compile(rb"(?is)(?:__nuitka|NUITKA_ONEFILE_PARENT|nuitka_constants|nuitka_loader)")),
    ("raw-ip-network-indicator", "Raw IP address network indicator", "low", re.compile(rb"(?i)\b(?:https?://)?(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b")),
    ("suspicious-tld-network-indicator", "Suspicious or abuse-prone TLD in URL", "medium", re.compile(rb"(?i)\bhttps?://[A-Za-z0-9.-]+\.(?:top|xyz|icu|click|quest|zip|mov|lol|monster|cyou|sbs|cam|shop|live)(?:[/:?#]|$)")),
    ("startup-persistence", "Windows startup persistence command", "high", re.compile(rb"(?is)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\\")),
])

AUTHENTICODE_CACHE: dict[tuple[str, int, int], tuple[str, str]] = {}
REDACTION_LEVELS = {"full", "secrets", "none"}

BIDI_CONTROL_CHARS = frozenset(chr(value) for value in range(0x202A, 0x202F)) | frozenset(chr(value) for value in range(0x2066, 0x206A))
SECRET_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
        "https://discord.com/api/webhooks/<redacted>",
    ),
    (
        re.compile(r"(?i)https://api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+"),
        "https://api.telegram.org/bot<redacted>",
    ),
    (
        re.compile(r"(?i)\b(bot|bearer|token|password|passwd|pwd|secret|api[_-]?key|authorization)\s*[:=]\s*['\"]?[^'\"\s;&|]{8,}"),
        r"\1=<redacted>",
    ),
    (re.compile(r"\b(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}\b"), "<redacted-token>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "<redacted-token>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted-access-key>"),
]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    detail: str
    evidence: str | None = None
    remediation: str | None = None


@dataclass
class ScanResult:
    path: str
    kind: str
    sha256: str | None = None
    size: int | None = None
    modified: str | None = None
    file_type: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def score(self) -> int:
        return sum(SEVERITY_SCORE.get(item.severity, 0) for item in self.findings)

    @property
    def verdict(self) -> str:
        if self.score >= 10:
            return "dangerous"
        if self.score >= 6:
            return "suspicious"
        if self.findings:
            return "review"
        if self.error:
            return "error"
        return "clean"


@dataclass
class ScanSummary:
    scanned_files: int
    skipped_files: int
    results: list[ScanResult]
    denied_files: int = 0
    vanished_files: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self, *, redact: bool | str = True) -> dict:
        return {
            "scanner": "CLN",
            "version": VERSION,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "denied_files": self.denied_files,
            "vanished_files": self.vanished_files,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "verdicts": verdict_counts(self.results),
            "hits": [
                {
                    "path": output_text(result.path, redact=redact),
                    "kind": output_text(result.kind, redact=redact),
                    "sha256": output_text(result.sha256, redact=redact) if result.sha256 else None,
                    "size": result.size,
                    "modified": output_text(result.modified, redact=redact) if result.modified else None,
                    "file_type": output_text(result.file_type, redact=redact) if result.file_type else None,
                    "verdict": result.verdict,
                    "score": result.score,
                    "error": output_text(result.error, redact=redact) if result.error else None,
                    "findings": [finding_to_dict(finding, redact=redact) for finding in result.findings],
                }
                for result in self.results
                if result.findings or result.error
            ],
        }


def finding_to_dict(finding: Finding, *, redact: bool | str = True) -> dict[str, str | None]:
    return {
        "rule_id": output_text(finding.rule_id, redact=redact),
        "title": output_text(finding.title, redact=redact),
        "severity": output_text(finding.severity, redact=redact),
        "detail": output_text(finding.detail, redact=redact),
        "evidence": output_text(finding.evidence, redact=redact) if finding.evidence else None,
        "remediation": output_text(finding.remediation, redact=redact) if finding.remediation else None,
    }


def output_text(value: object, *, redact: bool | str = True, limit: int | None = None) -> str:
    text = str(value)
    redaction_level = normalize_redaction_level(redact)
    if redaction_level != "none":
        text = redact_text(text, level=redaction_level)
    escaped = escape_control_text(text)
    if limit is not None and len(escaped) > limit:
        return f"{escaped[: max(0, limit - 3)]}..."
    return escaped


def normalize_redaction_level(redact: bool | str) -> str:
    if isinstance(redact, bool):
        return "full" if redact else "none"
    if redact not in REDACTION_LEVELS:
        raise ValueError(f"unsupported redaction level: {redact}")
    return redact


def redact_text(text: str, *, level: str = "full") -> str:
    if level not in REDACTION_LEVELS:
        raise ValueError(f"unsupported redaction level: {level}")
    if level == "full":
        home = str(Path.home())
        username = os.environ.get("USERNAME") or Path.home().name
        if username and len(username) >= 2:
            text = re.sub(rf"(?i)([\\/](?:users|documents and settings)[\\/]){re.escape(username)}(?=[\\/])", r"\1<user>", text)
            text = re.sub(rf"(?i)(\bC:[\\/]Users[\\/]){re.escape(username)}(?=[\\/])", r"\1<user>", text)
        if home:
            text = re.sub(re.escape(home), "~", text, flags=re.IGNORECASE)
            text = re.sub(re.escape(home.replace("\\", "/")), "~", text, flags=re.IGNORECASE)
    for pattern, replacement in SECRET_REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def escape_control_text(text: str) -> str:
    escaped: list[str] = []
    for char in text:
        codepoint = ord(char)
        if char == "\n":
            escaped.append(r"\n")
        elif char == "\r":
            escaped.append(r"\r")
        elif char == "\t":
            escaped.append(r"\t")
        elif codepoint < 32 or codepoint == 127:
            escaped.append(f"\\x{codepoint:02x}")
        elif char in BIDI_CONTROL_CHARS:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(char)
    return "".join(escaped)


class Scanner:
    def __init__(
        self,
        *,
        max_bytes: int,
        workers: int | None,
        known_bad: set[str],
        known_good: set[str],
        inspect_archives: bool,
        check_signatures: bool,
        include_source: bool,
        verbose: bool,
        recent_days: int,
        archive_depth: int = 2,
    ) -> None:
        self.max_bytes = max_bytes
        self.workers = workers or min(32, (os.cpu_count() or 4) + 4)
        self.known_bad = {item.lower() for item in known_bad}
        self.known_good = {item.lower() for item in known_good}
        self.inspect_archives = inspect_archives
        self.check_signatures = check_signatures and platform.system() == "Windows"
        self.include_source = include_source
        self.verbose = verbose
        self.recent_cutoff = datetime.now() - timedelta(days=recent_days)
        self.archive_depth = archive_depth

    def scan_paths(self, paths: Iterable[Path]) -> ScanSummary:
        started = datetime.now()
        if self.verbose:
            say("Loading targets", "Finding files for metadata checks; content scan size limit is applied later", "cyan")
        files, skipped = collect_files(paths, self.max_bytes)
        if self.verbose:
            say("Loaded", f"{len(files)} file(s), skipped {skipped}", "green")
            say("Scanning", f"{self.workers} worker(s), archives={'on' if self.inspect_archives else 'off'}, signatures={'deep' if self.check_signatures else 'fast'}", "cyan")
        results: list[ScanResult] = []
        denied_files = 0
        vanished_files = 0
        completed = 0
        next_tick = 100
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.scan_file, path): path for path in files}
            for future in as_completed(futures):
                result = future.result()
                if result.error and result.error.startswith("PermissionError:"):
                    denied_files += 1
                elif result.error and result.error.startswith("FileNotFoundError:"):
                    vanished_files += 1
                else:
                    results.append(result)
                completed += 1
                if self.verbose and len(files) >= 250 and completed >= next_tick:
                    say("Progress", f"{completed}/{len(files)} files", "dim")
                    next_tick += 250
        elapsed = (datetime.now() - started).total_seconds()
        return ScanSummary(
            len(files),
            skipped,
            sorted(results, key=lambda item: (-item.score, item.path.lower())),
            denied_files,
            vanished_files,
            elapsed,
        )

    def scan_file(self, path: Path) -> ScanResult:
        result = ScanResult(path=str(path), kind="file")
        try:
            info = path.stat()
            result.size = info.st_size
            result.modified = datetime.fromtimestamp(info.st_mtime).isoformat(timespec="seconds")
            result.sha256, sample = read_file_sample_and_hash(path)
            suffix = path.suffix.lower()
            result.file_type = detect_file_type(path, sample)

            trusted_hash = result.sha256.lower() in self.known_good
            if trusted_hash:
                result.findings.append(
                    Finding(
                        "trusted-hash",
                        "File hash is present in known-good allowlist",
                        "info",
                        result.sha256,
                        remediation="Keep the allowlist small and periodically re-verify trusted files from their original source.",
                    )
                )
            if result.sha256.lower() in self.known_bad:
                detail = BUILTIN_KNOWN_BAD_DETAILS.get(result.sha256.lower(), result.sha256)
                result.findings.append(Finding("known-bad-hash", "Known malicious hash", "critical", detail, remediation="Disconnect from the network if compromise is suspected, then quarantine or delete only after verifying the hash source."))

            self.scan_file_shape(path, result, info.st_mtime, suffix)
            result.findings.extend(scan_basic_document_content(path, sample, result.file_type))
            if result.size and result.size > self.max_bytes and should_queue_oversized_file(path):
                result.findings.append(Finding("oversized-risky-file", "Risky file exceeds content scan size limit", "low", f"size={format_bytes(result.size)}, limit={format_bytes(self.max_bytes)}", remediation="Inspect with a full antivirus scan or increase --max-mb for a deeper content scan."))

            if self.inspect_archives and should_inspect_archive(suffix, result.file_type):
                result.findings.extend(scan_zip(path, max_depth=self.archive_depth))
            elif self.inspect_archives and should_report_unsupported_archive(suffix, result.file_type):
                result.findings.extend(scan_unsupported_archive(path, result.file_type, sample))

            if not trusted_hash and should_scan_content(path, min(result.size or 0, len(sample)), result.file_type, include_source=self.include_source):
                result.findings.extend(scan_content_bytes(sample))

            if should_check_entropy(suffix, result.file_type):
                entropy = estimate_file_entropy(path, result.size or 0, sample)
                if entropy >= 7.4:
                    sample_note = "sliding-window" if (result.size or 0) > ENTROPY_SAMPLE_CHUNK_BYTES else "initial"
                    result.findings.append(Finding("packed-or-obfuscated", "High-entropy executable or script", "medium", f"{sample_note} entropy={entropy:.2f}"))

            if result.file_type in {"windows-pe", "mz-executable"}:
                result.findings.extend(analyze_pe_header(sample))

            if self.check_signatures and (suffix in SIGNED_APP_EXTENSIONS or result.file_type == "windows-pe"):
                self.scan_signature(path, result)
            self.apply_compound_rules(result)
        except Exception as exc:  # noqa: BLE001 - scanner should keep going.
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    def scan_file_shape(self, path: Path, result: ScanResult, mtime: float, suffix: str) -> None:
        if suffix in DANGEROUS_EXTENSIONS:
            result.findings.append(Finding("runnable-file", "Runnable file type", "medium", suffix, remediation="Run only if you expected this executable/script and trust its publisher or source."))

        if suffix in SOURCE_CODE_EXTENSIONS and (self.include_source or is_risky_location(path) or suffix == ".pyw"):
            severity = "medium" if is_risky_location(path) or suffix == ".pyw" else "low"
            result.findings.append(Finding("source-script", "Runnable source script", severity, suffix))

        if suffix in MACRO_DOCUMENT_EXTENSIONS:
            result.findings.append(Finding("macro-enabled-document", "Macro-enabled Office document", "medium", suffix))

        if result.file_type in {"windows-pe", "mz-executable"} and suffix not in PE_LIKE_EXTENSIONS:
            result.findings.append(
                Finding(
                    "renamed-executable",
                    "Executable content does not match the file extension",
                    "high",
                    f"extension={suffix or '(none)'}, detected={result.file_type}",
                )
            )

        if result.file_type == "windows-shortcut" and suffix != ".lnk":
            result.findings.append(Finding("renamed-shortcut", "Windows shortcut content does not match extension", "high", f"extension={suffix or '(none)'}"))

        if result.file_type == "zip-container" and suffix and suffix not in ZIP_CONTAINER_EXTENSIONS:
            result.findings.append(Finding("renamed-archive", "Zip archive content does not match extension", "medium", f"extension={suffix}"))

        expected_types = EXPECTED_FILE_TYPES_BY_EXTENSION.get(suffix)
        if expected_types and result.file_type and result.file_type != "unknown" and result.file_type not in expected_types:
            result.findings.append(
                Finding(
                    "file-type-mismatch",
                    "File content does not match extension",
                    "medium",
                    f"extension={suffix}, detected={result.file_type}",
                )
            )

        if is_double_extension(path):
            result.findings.append(Finding("double-extension", "File hides an executable behind a document-like name", "high", path.name))

        for detail, severity in suspicious_filename_flags(path.name):
            result.findings.append(Finding("suspicious-filename", "Suspicious filename characters", severity, detail))

        if is_hidden(path) and suffix in DANGEROUS_EXTENSIONS:
            result.findings.append(Finding("hidden-runnable", "Hidden runnable file", "medium", "Hidden attribute or dot-prefixed name"))

        if suffix in DANGEROUS_EXTENSIONS and datetime.fromtimestamp(mtime) >= self.recent_cutoff:
            result.findings.append(Finding("new-runnable", "New runnable file", "medium", f"modified {datetime.fromtimestamp(mtime).isoformat(timespec='seconds')}"))

        if suffix in DANGEROUS_EXTENSIONS and is_risky_location(path):
            result.findings.append(Finding("risky-location", "Runnable file is in a user-writable or download location", "medium", str(path.parent)))

        if suffix in SIGNED_APP_EXTENSIONS and path.name.lower() in {"setup.exe", "installer.exe", "update.exe", "security.exe", "verify.exe"} and is_risky_location(path):
            result.findings.append(Finding("generic-installer-name", "Generic installer name in risky location", "low", path.name, remediation="Use this as supporting context; generic installer names are common but should match the expected download."))

        for pattern in suspicious_name_hits(path):
            result.findings.append(Finding("suspicious-name", "Suspicious scam-like filename", "medium", pattern))

    def scan_signature(self, path: Path, result: ScanResult) -> None:
        status, signer = authenticode_status(path)
        if status == "Valid":
            return
        if status == "NotSigned":
            result.findings.append(Finding("unsigned-app", "Runnable app is not signed", "medium", "Unsigned apps are harder to trust"))
        elif status == "UnknownError":
            result.findings.append(Finding("signature-check-failed", "Authenticode signature check failed", "low", signer or "Signature status unavailable"))
        elif status:
            result.findings.append(Finding("bad-signature", "Runnable app has an invalid or untrusted signature", "high", status))

    def apply_compound_rules(self, result: ScanResult) -> None:
        rule_ids = {finding.rule_id for finding in result.findings}
        if {"unsigned-app", "risky-location", "packed-or-obfuscated"}.issubset(rule_ids) and "compound-unsigned-packed-risky" not in rule_ids:
            result.findings.append(
                Finding(
                    "compound-unsigned-packed-risky",
                    "Unsigned packed app in risky location",
                    "critical",
                    "Unsigned, high-entropy runnable file located in a user-writable or download location",
                )
            )
        if {"generic-installer-name", "risky-location", "new-runnable"}.issubset(rule_ids) and "compound-new-generic-installer" not in rule_ids:
            result.findings.append(
                Finding(
                    "compound-new-generic-installer",
                    "New generic installer in risky location",
                    "medium",
                    "Generic installer naming combined with recent modification time and risky location",
                    remediation="Confirm the download origin and signature before running the installer.",
                )
            )
        if {"ps-encoded-command", "risky-location"}.issubset(rule_ids) and "compound-encoded-powershell-risky-location" not in rule_ids:
            result.findings.append(
                Finding(
                    "compound-encoded-powershell-risky-location",
                    "Encoded PowerShell in risky location",
                    "critical",
                    "Encoded PowerShell content combined with a user-writable or download location",
                    remediation="Treat as high priority until the encoded command is decoded and verified.",
                )
            )
        if {"archive-runnable", "archive-suspicious-name"}.issubset(rule_ids) and "compound-scam-archive-runnable" not in rule_ids:
            result.findings.append(
                Finding(
                    "compound-scam-archive-runnable",
                    "Scam-themed archive contains runnable content",
                    "high",
                    "Archive naming indicators combined with executable or script content",
                    remediation="Do not extract or run the archive contents until the source is verified.",
                )
            )


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be at least 0")
    return parsed


def worker_count(value: str) -> int:
    parsed = positive_int(value)
    if parsed > 64:
        raise argparse.ArgumentTypeError("must be between 1 and 64")
    return parsed


def archive_depth(value: str) -> int:
    parsed = non_negative_int(value)
    if parsed > 8:
        raise argparse.ArgumentTypeError("must be between 0 and 8")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cln",
        description="Single-file open-source scanner for scam downloads, weird new apps, unsigned apps, and malware warning signs.",
    )
    parser.add_argument("paths", nargs="*", type=Path, help="Files or folders to scan. Defaults to Downloads, Desktop, Documents, and temp.")
    parser.add_argument("--full", action="store_true", help="Scan the whole user profile.")
    parser.add_argument("--startup", action="store_true", help="Inspect Windows startup folders and registry Run keys.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--csv", action="store_true", help="Print findings as CSV.")
    parser.add_argument("--sarif", type=Path, help="Write a SARIF 2.1.0 report for code-scanning or CI ingestion.")
    parser.add_argument("--baseline", type=Path, help="Compare against a previous CLN JSON report and only keep new matching findings.")
    parser.add_argument("--rules", type=Path, help="Load extra content rules from a structured JSON rule file.")
    parser.add_argument("--yara-rules", type=Path, help="Run optional yara-python rules from this file or directory when yara-python is installed.")
    parser.add_argument("--max-mb", type=positive_int, default=75, help="Content scan size limit in MB. Metadata and magic bytes are still inspected for larger files. Default: 75.")
    parser.add_argument("--workers", type=worker_count, default=None, help="Parallel worker count from 1 to 64. Default: auto.")
    parser.add_argument("--known-bad", type=Path, help="JSON array of known bad SHA-256 hashes.")
    parser.add_argument("--known-good", type=Path, help="JSON array of trusted SHA-256 hashes.")
    parser.add_argument("--no-archives", action="store_true", help="Do not inspect zip archive entry names.")
    parser.add_argument("--archive-depth", type=archive_depth, default=2, help="Maximum nested zip recursion depth from 0 to 8. Default: 2.")
    parser.add_argument("--signatures", action="store_true", help="Deep-check Windows Authenticode signatures. Slower; off by default.")
    parser.add_argument("--include-source", action="store_true", help="Also scan source-code scripts outside risky locations. More thorough, more review noise.")
    parser.add_argument("--quiet", action="store_true", help="Only print the final report.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--redact-level", choices=sorted(REDACTION_LEVELS), default="full", help="Redaction level for output: full, secrets, or none. Default: full.")
    parser.add_argument("--no-redact", action="store_true", help="Do not redact paths, tokens, or evidence in terminal, JSON, and text reports.")
    parser.add_argument("--recent-days", type=non_negative_int, default=14, help="Treat runnable files newer than this as new apps. Default: 14.")
    parser.add_argument("--clean", action="store_true", help="Quarantine built-in confirmed known-bad files found by SHA-256.")
    parser.add_argument("--clean-user-hashes", action="store_true", help="With --clean, also quarantine hashes supplied through --known-bad.")
    parser.add_argument("--delete", action="store_true", help="With --clean, permanently delete built-in confirmed known-bad files instead of quarantining.")
    parser.add_argument("--quarantine-dir", type=Path, default=Path("quarantine"), help="Where --clean stores removed files. Default: .\\quarantine")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"), help="Where readable text reports are saved. Default: .\\reports")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.json and args.csv:
        parser.error("--json and --csv cannot be used together")
    global COLOR_ENABLED
    if args.no_color or args.json or args.csv:
        COLOR_ENABLED = False
    redact_outputs = "none" if args.no_redact else args.redact_level
    paths = choose_paths(args)
    verbose = not args.quiet and not args.json and not args.csv
    user_known_bad = load_hashes(args.known_bad)
    if args.rules:
        CONTENT_RULES.extend(load_content_rules(args.rules))
    cleanable_hashes = BUILTIN_KNOWN_BAD_SHA256 | (user_known_bad if args.clean_user_hashes else set())
    if verbose:
        print_banner()
        say("Mode", "fast scan; deep signature checks are off unless --signatures is used", "cyan")
        say("Loading", "rules, hash blocklist, file-type probes, archive checks, startup checks if requested", "cyan")
    scanner = Scanner(
        max_bytes=args.max_mb * 1024 * 1024,
        workers=args.workers,
        known_bad=BUILTIN_KNOWN_BAD_SHA256 | user_known_bad,
        known_good=load_hashes(args.known_good),
        inspect_archives=not args.no_archives,
        check_signatures=args.signatures,
        include_source=args.include_source,
        verbose=verbose,
        recent_days=args.recent_days,
        archive_depth=args.archive_depth,
    )
    summary = scanner.scan_paths(paths)
    if args.yara_rules:
        apply_yara_rules(summary, args.yara_rules)
    if args.startup:
        if verbose:
            say("Startup", "Checking folders, registry persistence, tasks, WMI, and browser extensions", "cyan")
        startup_results = scan_startup_locations()
        summary.results.extend(startup_results)
        summary.results.sort(key=lambda item: (-item.score, item.path.lower()))

    cleanup_report: list[str] = []
    if args.clean:
        cleanup_report = clean_known_bad(summary, args.quarantine_dir, delete=args.delete, cleanable_hashes=cleanable_hashes)

    if args.baseline:
        summary = filter_baseline(summary, args.baseline, redact=redact_outputs)

    report_path: Path | None = None
    report_error: str | None = None
    try:
        report_path = write_text_report(summary, paths, cleanup_report, args.report_dir, scanner.check_signatures, redact=redact_outputs)
    except Exception as exc:  # noqa: BLE001 - scan results are more important than report persistence.
        report_error = f"{type(exc).__name__}: {exc}"

    sarif_error: str | None = None
    if args.sarif:
        try:
            write_sarif_report(summary, args.sarif, redact=redact_outputs)
        except Exception as exc:  # noqa: BLE001
            sarif_error = f"{type(exc).__name__}: {exc}"

    if args.json:
        data = summary.to_dict(redact=redact_outputs)
        data["redacted"] = redact_outputs != "none"
        data["redaction_level"] = redact_outputs
        data["cleanup"] = [output_text(line, redact=redact_outputs) for line in cleanup_report]
        data["report_path"] = output_text(report_path, redact=redact_outputs) if report_path else None
        data["report_error"] = output_text(report_error, redact=redact_outputs) if report_error else None
        data["sarif_path"] = output_text(args.sarif, redact=redact_outputs) if args.sarif and not sarif_error else None
        data["sarif_error"] = output_text(sarif_error, redact=redact_outputs) if sarif_error else None
        print(json.dumps(data, indent=2))
    elif args.csv:
        print(summary_to_csv(summary, redact=redact_outputs), end="")
    else:
        print_report(summary, paths, scanner.check_signatures, redact=redact_outputs)
        if cleanup_report:
            print("")
            print("Cleanup:")
            for line in cleanup_report:
                print(f"  - {output_text(line, redact=redact_outputs)}")
        if report_error:
            print("")
            print(color(f"Report warning: could not save text report: {output_text(report_error, redact=redact_outputs)}", "yellow"))
        if sarif_error:
            print("")
            print(color(f"SARIF warning: could not save SARIF report: {output_text(sarif_error, redact=redact_outputs)}", "yellow"))
        print("")
        if report_path:
            print(color(f"Scan complete. Review: {output_text(report_path, redact=redact_outputs)}", "green"))
        else:
            print(color("Scan complete. Text report was not saved.", "green"))
    return 2 if any(result.verdict in {"dangerous", "suspicious"} for result in summary.results) else 0


def choose_paths(args: argparse.Namespace) -> list[Path]:
    if args.paths:
        return args.paths
    if args.full:
        return [Path.home()]
    return default_quick_paths()


def print_banner() -> None:
    print(color(f"CLN Scanner {VERSION}", "bold"))
    print(color("Fast local scan. No network calls. No cleanup unless --clean is used.", "dim"))


def color(text: str, name: str) -> str:
    if not COLOR_ENABLED:
        return text
    return f"{COLORS.get(name, '')}{text}{COLORS['reset']}"


def say(label: str, detail: str, tone: str = "cyan") -> None:
    print(f"{color(label + ':', tone)} {output_text(detail)}")


def severity_label(severity: str) -> str:
    tone = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}.get(severity, "dim")
    return color(severity.upper(), tone)


def verdict_label(verdict: str) -> str:
    tone = {"dangerous": "red", "suspicious": "yellow", "review": "cyan", "error": "red", "clean": "green"}.get(verdict, "dim")
    return color(f"[{verdict.upper()}]", tone)


def summary_to_csv(summary: ScanSummary, *, redact: bool = True) -> str:
    output = io.StringIO(newline="")
    fieldnames = [
        "path",
        "kind",
        "verdict",
        "score",
        "severity",
        "rule_id",
        "title",
        "detail",
        "evidence",
        "sha256",
        "size",
        "modified",
        "file_type",
        "error",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for result in summary.results:
        if not result.findings and not result.error:
            continue
        base = {
            "path": output_text(result.path, redact=redact),
            "kind": output_text(result.kind, redact=redact),
            "verdict": result.verdict,
            "score": result.score,
            "sha256": output_text(result.sha256, redact=redact) if result.sha256 else "",
            "size": result.size if result.size is not None else "",
            "modified": output_text(result.modified, redact=redact) if result.modified else "",
            "file_type": output_text(result.file_type, redact=redact) if result.file_type else "",
            "error": output_text(result.error, redact=redact) if result.error else "",
        }
        if result.findings:
            for finding in result.findings:
                row = dict(base)
                row.update(
                    {
                        "severity": output_text(finding.severity, redact=redact),
                        "rule_id": output_text(finding.rule_id, redact=redact),
                        "title": output_text(finding.title, redact=redact),
                        "detail": output_text(finding.detail, redact=redact),
                        "evidence": output_text(finding.evidence, redact=redact) if finding.evidence else "",
                    }
                )
                writer.writerow(row)
        else:
            writer.writerow({**base, "severity": "", "rule_id": "", "title": "", "detail": "", "evidence": ""})
    return output.getvalue()


def write_sarif_report(summary: ScanSummary, path: Path, *, redact: bool = True) -> None:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    severity_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for result in summary.results:
        for finding in result.findings:
            rules.setdefault(
                finding.rule_id,
                {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "help": {"text": finding.remediation or "Review the CLN finding and verify the file source."},
                    "properties": {"severity": finding.severity},
                },
            )
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": severity_level.get(finding.severity, "warning"),
                    "message": {"text": output_text(f"{finding.title}: {finding.detail}", redact=redact)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": output_text(result.path, redact=redact)},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CLN",
                        "version": VERSION,
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    secure_write_text_file(path, json.dumps(sarif, indent=2))


def filter_baseline(summary: ScanSummary, baseline_path: Path, *, redact: bool = True) -> ScanSummary:
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    old_keys: set[tuple[str, str, str | None]] = set()
    for hit in data.get("hits", []):
        path = str(hit.get("path", ""))
        sha256_value = hit.get("sha256")
        for finding in hit.get("findings", []):
            old_keys.add((path, str(finding.get("rule_id", "")), sha256_value))
    filtered_results: list[ScanResult] = []
    for result in summary.results:
        if not result.findings:
            if result.error:
                filtered_results.append(result)
            continue
        kept = [
            finding
            for finding in result.findings
            if (output_text(result.path, redact=redact), finding.rule_id, output_text(result.sha256, redact=redact) if result.sha256 else None) not in old_keys
        ]
        if kept or result.error:
            filtered_results.append(
                ScanResult(
                    path=result.path,
                    kind=result.kind,
                    sha256=result.sha256,
                    size=result.size,
                    modified=result.modified,
                    file_type=result.file_type,
                    findings=kept,
                    error=result.error,
                )
            )
    return ScanSummary(
        scanned_files=summary.scanned_files,
        skipped_files=summary.skipped_files,
        results=filtered_results,
        denied_files=summary.denied_files,
        vanished_files=summary.vanished_files,
        elapsed_seconds=summary.elapsed_seconds,
    )


def apply_yara_rules(summary: ScanSummary, rules_path: Path) -> None:
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        warning = Finding(
            "yara-unavailable",
            "YARA rules were requested but yara-python is not installed",
            "low",
            str(rules_path),
            remediation="Install optional dependency yara-python, then rerun with --yara-rules.",
        )
        summary.results.append(ScanResult(path=str(rules_path), kind="yara", findings=[warning]))
        return

    try:
        if rules_path.is_dir():
            filepaths = {str(path): str(path) for path in rules_path.rglob("*.yar")}
            filepaths.update({str(path): str(path) for path in rules_path.rglob("*.yara")})
            rules = yara.compile(filepaths=filepaths)
        else:
            rules = yara.compile(filepath=str(rules_path))
    except Exception as exc:  # noqa: BLE001
        summary.results.append(
            ScanResult(
                path=str(rules_path),
                kind="yara",
                findings=[Finding("yara-compile-error", "YARA rules could not be compiled", "medium", f"{type(exc).__name__}: {exc}")],
            )
        )
        return

    for result in summary.results:
        if result.kind != "file" or result.error:
            continue
        try:
            matches = rules.match(result.path)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(Finding("yara-scan-error", "YARA scan failed for file", "low", f"{type(exc).__name__}: {exc}"))
            continue
        for match in matches:
            result.findings.append(
                Finding(
                    "yara-match",
                    f"YARA match: {match.rule}",
                    "high",
                    getattr(match, "namespace", "") or str(rules_path),
                    remediation="Treat YARA matches as high-signal and validate with your incident-response workflow.",
                )
            )


def print_report(summary: ScanSummary, paths: list[Path], signatures_enabled: bool, *, redact: bool = True) -> None:
    print("")
    print(color(f"CLN Scanner {VERSION}", "bold"))
    print(color("Open source check: this single file is the scanner. Read cln.py to audit exactly what runs.", "dim"))
    print(f"{color('Targets:', 'cyan')} {output_text(', '.join(str(path) for path in paths) or '(none found)', redact=redact)}")
    total_skipped = summary.skipped_files + summary.vanished_files
    print(f"{color('Scanned:', 'cyan')} {summary.scanned_files} file(s), skipped: {total_skipped}")
    if summary.vanished_files:
        print(f"{color('Vanished:', 'dim')} {summary.vanished_files} temp/transient file(s) disappeared during scan.")
    if summary.denied_files:
        print(f"{color('Access denied:', 'yellow')} {summary.denied_files} locked/protected file(s) could not be opened.")
        if platform.system() == "Windows" and not is_admin():
            print(color("Run PowerShell or Command Prompt as Administrator for a deeper scan.", "yellow"))
    if platform.system() == "Windows":
        print(f"{color('Signature checks:', 'cyan')} {'deep' if signatures_enabled else 'fast/off'}")
    if summary.elapsed_seconds:
        print(f"{color('Elapsed:', 'cyan')} {summary.elapsed_seconds:.2f}s")
    counts = verdict_counts(summary.results)
    if any(counts.values()):
        print(
            f"{color('Verdicts:', 'cyan')} "
            f"dangerous={counts['dangerous']}, suspicious={counts['suspicious']}, review={counts['review']}, clean={counts['clean']}, error={counts['error']}"
        )

    hits = [result for result in summary.results if result.findings or result.error]
    if not hits:
        print(color("No suspicious files found.", "green"))
        return

    print(f"{color('Findings:', 'yellow')} {len(hits)}")
    for result in hits:
        print("")
        print(f"{verdict_label(result.verdict)} {output_text(result.path, redact=redact)}")
        if result.size is not None:
            print(f"  Size: {result.size} bytes")
        if result.modified:
            print(f"  Modified: {output_text(result.modified, redact=redact)}")
        if result.file_type:
            print(f"  Type: {output_text(result.file_type, redact=redact)}")
        if result.sha256:
            print(f"  SHA-256: {output_text(result.sha256, redact=redact)}")
        if result.error:
            print(f"  {color('Error:', 'red')} {output_text(result.error, redact=redact)}")
        for finding in result.findings:
            if finding.severity == "info":
                continue
            print(f"  - {severity_label(finding.severity)} {output_text(finding.rule_id, redact=redact)}: {output_text(finding.title, redact=redact)}")
            print(f"    {output_text(finding.detail, redact=redact)}")
            if finding.evidence:
                print(f"    Evidence: {output_text(finding.evidence, redact=redact)}")
            if finding.remediation:
                print(f"    Remediation: {output_text(finding.remediation, redact=redact)}")


def write_text_report(
    summary: ScanSummary,
    paths: list[Path],
    cleanup_report: list[str],
    report_dir: Path,
    signatures_enabled: bool,
    *,
    redact: bool = True,
) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    report_path = report_dir / f"cln-scan-{timestamp}.txt"
    hits = [result for result in summary.results if result.findings or result.error]
    counts = verdict_counts(summary.results)

    lines = [
        f"CLN Scanner {VERSION}",
        f"Report created: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "Summary",
        f"  Targets: {output_text(', '.join(str(path) for path in paths) or '(none found)', redact=redact)}",
        f"  Scanned files: {summary.scanned_files}",
        f"  Skipped files: {summary.skipped_files + summary.vanished_files}",
        f"  Access denied: {summary.denied_files}",
        f"  Vanished during scan: {summary.vanished_files}",
        f"  Signature checks: {'deep' if signatures_enabled else 'fast/off'}",
        f"  Elapsed seconds: {summary.elapsed_seconds:.2f}",
        f"  Verdicts: dangerous={counts['dangerous']}, suspicious={counts['suspicious']}, review={counts['review']}, clean={counts['clean']}, error={counts['error']}",
        f"  Findings: {len(hits)}",
        "",
    ]

    if summary.denied_files:
        lines.extend(
            [
                "Access Note",
                "  Some locked or protected files could not be opened.",
                "  For a deeper scan on Windows, run PowerShell or Command Prompt as Administrator.",
                "",
            ]
        )

    if hits:
        lines.append("Findings")
        for result in hits:
            lines.extend(
                [
                    "",
                    f"[{result.verdict.upper()}] {output_text(result.path, redact=redact)}",
                    f"  Kind: {output_text(result.kind, redact=redact)}",
                    f"  Size: {result.size if result.size is not None else 'unknown'}",
                    f"  Modified: {output_text(result.modified or 'unknown', redact=redact)}",
                    f"  Type: {output_text(result.file_type or 'unknown', redact=redact)}",
                    f"  SHA-256: {output_text(result.sha256 or 'not available', redact=redact)}",
                ]
            )
            if result.error:
                lines.append(f"  Error: {output_text(result.error, redact=redact)}")
            for finding in result.findings:
                lines.extend(
                    [
                        f"  - {output_text(finding.severity.upper(), redact=redact)} {output_text(finding.rule_id, redact=redact)}: {output_text(finding.title, redact=redact)}",
                        f"    {output_text(finding.detail, redact=redact)}",
                    ]
                )
                if finding.evidence:
                    lines.append(f"    Evidence: {output_text(finding.evidence, redact=redact)}")
                if finding.remediation:
                    lines.append(f"    Remediation: {output_text(finding.remediation, redact=redact)}")
    else:
        lines.extend(["Findings", "  No suspicious files found."])

    if cleanup_report:
        lines.extend(["", "Cleanup"])
        lines.extend(f"  - {output_text(line, redact=redact)}" for line in cleanup_report)

    lines.extend(
        [
            "",
            "Safety",
            "  CLN is one security layer. No scanner can catch every threat.",
            "  Review suspicious files before deleting anything that was not confirmed by hash.",
            "",
        ]
    )
    secure_write_text_file(report_path, "\n".join(lines))
    return report_path


def collect_files(paths: Iterable[Path], max_bytes: int) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0
    for root in paths:
        try:
            if root.is_file():
                root.stat()
                files.append(root)
                continue
            if not root.is_dir():
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue

        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if not is_excluded_path(path):
                                    stack.append(path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            if is_excluded_path(path):
                                continue
                            entry.stat(follow_symlinks=False)
                            files.append(path)
                        except OSError:
                            skipped += 1
            except OSError:
                skipped += 1
    return files, skipped


def should_queue_oversized_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return (
        suffix in DANGEROUS_EXTENSIONS
        or suffix in ARCHIVE_EXTENSIONS
        or suffix in UNSUPPORTED_ARCHIVE_EXTENSIONS
        or suffix in SOURCE_CODE_EXTENSIONS
        or is_double_extension(path)
        or bool(suspicious_name_hits(path))
        or bool(suspicious_filename_flags(path.name))
    )


def is_excluded_path(path: Path) -> bool:
    return any(part.lower() in DEFAULT_EXCLUDED_DIRS for part in path.parts)


def default_quick_paths() -> list[Path]:
    home = Path.home()
    candidates = [
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
    ]
    temp = os.environ.get("TEMP")
    if temp:
        candidates.append(Path(temp))
    return [path for path in candidates if str(path) and path.exists()]


def load_hashes(path: Path | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        hashes = {str(item).strip().lower() for item in data}
    elif isinstance(data, dict):
        schema = str(data.get("schema") or data.get("schema_version") or "")
        if schema and schema not in {"cln-hash-list-v1", "1"}:
            raise ValueError(f"{path} uses unsupported hash-list schema: {schema}")
        hashes_value = data.get("hashes")
        if not isinstance(hashes_value, list):
            raise ValueError(f"{path} must contain a 'hashes' array")
        if not data.get("description"):
            raise ValueError(f"{path} structured hash list requires a description")
        if not data.get("created_at") and not data.get("updated_at"):
            raise ValueError(f"{path} structured hash list requires created_at or updated_at")
        hashes = set()
        for item in hashes_value:
            if isinstance(item, dict):
                hashes.add(str(item.get("sha256", "")).strip().lower())
            else:
                hashes.add(str(item).strip().lower())
    else:
        raise ValueError(f"{path} must contain a JSON array or structured hash-list object")
    bad_values = [item for item in hashes if not re.fullmatch(r"[a-f0-9]{64}", item)]
    if bad_values:
        raise ValueError(f"{path} contains invalid SHA-256 value(s): {', '.join(bad_values[:3])}")
    return hashes


def load_content_rules(path: Path) -> list[ContentRule]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a structured JSON rule object")
    schema = str(data.get("schema") or data.get("schema_version") or "")
    if schema and schema not in {"cln-content-rules-v1", "1"}:
        raise ValueError(f"{path} uses unsupported rule schema: {schema}")
    rules_value = data.get("rules")
    if not isinstance(rules_value, list):
        raise ValueError(f"{path} must contain a rules array")
    loaded: list[ContentRule] = []
    for index, item in enumerate(rules_value):
        if not isinstance(item, dict):
            raise ValueError(f"{path} rule #{index + 1} must be an object")
        rule_id = str(item.get("id") or item.get("rule_id") or "").strip()
        title = str(item.get("title") or rule_id).strip()
        severity = str(item.get("severity") or "medium").strip().lower()
        pattern = str(item.get("pattern") or "")
        flags_text = str(item.get("flags") or "is")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", rule_id):
            raise ValueError(f"{path} rule #{index + 1} has an invalid id")
        if severity not in SEVERITY_SCORE:
            raise ValueError(f"{path} rule {rule_id} has invalid severity: {severity}")
        flags = 0
        if "i" in flags_text:
            flags |= re.IGNORECASE
        if "s" in flags_text:
            flags |= re.DOTALL
        if "m" in flags_text:
            flags |= re.MULTILINE
        try:
            regex = re.compile(pattern.encode("utf-8"), flags)
        except re.error as exc:
            raise ValueError(f"{path} rule {rule_id} has invalid regex: {exc}") from exc
        remediation = str(item.get("remediation") or "Review this rule match and verify the file source.")
        loaded.append(ContentRule(rule_id, title, severity, regex, remediation))
    return loaded


def secure_write_text_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if platform.system() != "Windows":
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        return
    with path.open("x", encoding="utf-8") as handle:
        handle.write(text)
    restrict_windows_file_acl(path)


def restrict_windows_file_acl(path: Path) -> None:
    if platform.system() != "Windows":
        return
    icacls = shutil.which("icacls")
    if not icacls:
        return
    subprocess.run([icacls, str(path), "/inheritance:r"], capture_output=True, text=True, timeout=10, check=False)
    user = os.environ.get("USERNAME")
    if user:
        subprocess.run([icacls, str(path), "/grant:r", f"{user}:F"], capture_output=True, text=True, timeout=10, check=False)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_file_sample_and_hash(path: Path, sample_limit: int = MAX_TEXT_SCAN_BYTES) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    sample = bytearray()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            if len(sample) < sample_limit:
                needed = sample_limit - len(sample)
                sample.extend(chunk[:needed])
    return digest.hexdigest(), bytes(sample)


def read_entropy_sample(path: Path, size: int, chunk_size: int = ENTROPY_SAMPLE_CHUNK_BYTES) -> bytes:
    if size <= 0:
        return b""
    offsets = [0]
    if size > chunk_size * 2:
        offsets.append(max(0, (size // 2) - (chunk_size // 2)))
    if size > chunk_size:
        offsets.append(max(0, size - chunk_size))
    sample = bytearray()
    seen_offsets: set[int] = set()
    with path.open("rb") as handle:
        for offset in offsets:
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)
            handle.seek(offset)
            sample.extend(handle.read(chunk_size))
    return bytes(sample)


def estimate_file_entropy(path: Path, size: int, initial_sample: bytes) -> float:
    if size <= ENTROPY_SAMPLE_CHUNK_BYTES or size <= len(initial_sample):
        return estimate_entropy_bytes(initial_sample)
    return max_sliding_window_entropy(path, size)


def max_sliding_window_entropy(path: Path, size: int, chunk_size: int = ENTROPY_SAMPLE_CHUNK_BYTES, max_windows: int = MAX_ENTROPY_WINDOWS) -> float:
    if size <= 0:
        return 0.0
    if size <= chunk_size:
        try:
            return estimate_entropy_bytes(path.read_bytes())
        except OSError:
            return 0.0
    window_count = min(max_windows, max(1, math.ceil(size / chunk_size)))
    max_start = max(0, size - chunk_size)
    offsets = sorted({round(index * max_start / max(1, window_count - 1)) for index in range(window_count)})
    highest = 0.0
    with path.open("rb") as handle:
        for offset in offsets:
            handle.seek(offset)
            data = handle.read(chunk_size)
            if not data:
                continue
            highest = max(highest, estimate_entropy_bytes(data))
    return highest


def analyze_pe_header(sample: bytes) -> list[Finding]:
    if not sample.startswith(b"MZ") or len(sample) < 0x40:
        return []
    pe_offset = int.from_bytes(sample[0x3C:0x40], "little", signed=False)
    if pe_offset < 0 or pe_offset > len(sample) - 24 or sample[pe_offset : pe_offset + 4] != b"PE\0\0":
        return []
    file_header = pe_offset + 4
    section_count = int.from_bytes(sample[file_header + 2 : file_header + 4], "little", signed=False)
    optional_size = int.from_bytes(sample[file_header + 16 : file_header + 18], "little", signed=False)
    optional_offset = file_header + 20
    section_offset = optional_offset + optional_size
    if section_count <= 0 or section_count > 96 or section_offset > len(sample):
        return []
    entry_point_rva = 0
    if optional_size >= 20 and optional_offset + 20 <= len(sample):
        magic = int.from_bytes(sample[optional_offset : optional_offset + 2], "little", signed=False)
        if magic in {0x10B, 0x20B}:
            entry_point_rva = int.from_bytes(sample[optional_offset + 16 : optional_offset + 20], "little", signed=False)

    findings: list[Finding] = []
    entry_section_name = ""
    for index in range(section_count):
        offset = section_offset + (index * 40)
        if offset + 40 > len(sample):
            findings.append(Finding("pe-truncated-section-table", "PE section table is truncated", "low", f"sections={section_count}, parsed={index}"))
            break
        raw_name = sample[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section-{index}"
        virtual_size = int.from_bytes(sample[offset + 8 : offset + 12], "little", signed=False)
        virtual_address = int.from_bytes(sample[offset + 12 : offset + 16], "little", signed=False)
        characteristics = int.from_bytes(sample[offset + 36 : offset + 40], "little", signed=False)
        executable = bool(characteristics & 0x20000000)
        writable = bool(characteristics & 0x80000000)
        if executable and writable:
            findings.append(Finding("pe-writable-code-section", "PE executable section is writable", "high", f"{name} characteristics=0x{characteristics:08x}"))
        if entry_point_rva and virtual_address <= entry_point_rva < virtual_address + max(virtual_size, 1):
            entry_section_name = name
            if not executable:
                findings.append(Finding("pe-entrypoint-not-executable", "PE entry point is in a non-executable section", "medium", f"{name} rva=0x{entry_point_rva:x}"))

    if entry_point_rva and not entry_section_name:
        findings.append(Finding("pe-entrypoint-outside-sections", "PE entry point is outside declared sections", "high", f"rva=0x{entry_point_rva:x}"))
    elif entry_section_name and entry_section_name.lower() not in {".text", "code", ".code", "text"}:
        findings.append(Finding("pe-unusual-entrypoint-section", "PE entry point is in an unusual section", "low", entry_section_name))
    return findings


def detect_file_type(path: Path, sample: bytes) -> str:
    stripped = sample[:512].lstrip()
    suffix = path.suffix.lower()
    if sample.startswith(b"MZ"):
        if len(sample) >= 0x40:
            pe_offset = int.from_bytes(sample[0x3C:0x40], "little", signed=False)
            if 0 <= pe_offset <= len(sample) - 4 and sample[pe_offset : pe_offset + 4] == b"PE\0\0":
                return "windows-pe"
        return "mz-executable"
    if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip-container"
    if sample.startswith(b"%PDF-"):
        return "pdf-document"
    if sample.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "compound-document"
    if sample.startswith(b"\x7fELF"):
        return "elf-binary"
    if sample.startswith((b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF", b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE")):
        return "macho-binary"
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png-image"
    if sample.startswith(b"\xff\xd8\xff"):
        return "jpeg-image"
    if sample.startswith((b"GIF87a", b"GIF89a")):
        return "gif-image"
    if sample.startswith(b"Rar!\x1A\x07"):
        return "rar-archive"
    if sample.startswith(b"7z\xBC\xAF\x27\x1C"):
        return "7z-archive"
    if sample.startswith(b"MSCF"):
        return "cab-archive"
    if b"Rar!\x1A\x07" in sample[:262_144] or b"7z\xBC\xAF\x27\x1C" in sample[:262_144]:
        return "self-extracting-archive"
    if sample.startswith(b"\x4C\x00\x00\x00\x01\x14\x02\x00"):
        return "windows-shortcut"
    if stripped.startswith(b"#!"):
        return "script-text"
    if stripped[:64].lower().startswith((b"<!doctype html", b"<html", b"<script")):
        return "html-text"
    if suffix in TEXT_CONTENT_EXTENSIONS or suffix in SOURCE_CODE_EXTENSIONS or suffix == ".txt":
        return "text-script-or-document"
    return "unknown"


def should_inspect_archive(suffix: str, file_type: str | None) -> bool:
    return suffix in ZIP_CONTAINER_EXTENSIONS or file_type == "zip-container"


def should_report_unsupported_archive(suffix: str, file_type: str | None) -> bool:
    return suffix in UNSUPPORTED_ARCHIVE_EXTENSIONS or file_type in {"rar-archive", "7z-archive", "cab-archive", "self-extracting-archive"}


def should_check_entropy(suffix: str, file_type: str | None) -> bool:
    return suffix in DANGEROUS_EXTENSIONS or suffix in SOURCE_CODE_EXTENSIONS or suffix in UNSUPPORTED_ARCHIVE_EXTENSIONS or file_type in {"windows-pe", "mz-executable", "elf-binary", "macho-binary", "self-extracting-archive"}


def is_double_extension(path: Path) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in DANGEROUS_EXTENSIONS and suffixes[-2] in DOCUMENT_EXTENSIONS


def suspicious_name_hits(path: Path) -> list[str]:
    return suspicious_name_hits_text(path.name)


def suspicious_name_hits_text(name: str) -> list[str]:
    text = re.sub(r"[^A-Za-z0-9]+", " ", name)
    return [pattern.pattern for pattern in SUSPICIOUS_NAME_PATTERNS if pattern.search(text)]


def suspicious_filename_flags(name: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    controls = {
        "\u202a": "left-to-right embedding",
        "\u202b": "right-to-left embedding",
        "\u202d": "left-to-right override",
        "\u202e": "right-to-left override",
        "\u2066": "left-to-right isolate",
        "\u2067": "right-to-left isolate",
        "\u2068": "first-strong isolate",
        "\u2069": "pop directional isolate",
    }
    used_controls = [label for char, label in controls.items() if char in name]
    if used_controls:
        findings.append((f"Unicode direction control in filename: {', '.join(used_controls)}", "high"))
    if re.search(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png)\s+\.(?:exe|scr|bat|cmd|ps1|js|vbs)$", name):
        findings.append(("Whitespace-separated double extension", "high"))
    if re.search(r"[\u200b\u200c\u200d\ufeff]", name):
        findings.append(("Zero-width Unicode character in filename", "medium"))
    return findings


def verdict_counts(results: list[ScanResult]) -> dict[str, int]:
    counts = {"dangerous": 0, "suspicious": 0, "review": 0, "clean": 0, "error": 0}
    for result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1
    return counts


def is_hidden(path: Path) -> bool:
    if path.name.startswith("."):
        return True
    if platform.system() != "Windows":
        return False
    try:
        return bool(path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
    except (AttributeError, OSError):
        return False


def is_admin() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - advisory only.
        return False


def is_risky_location(path: Path) -> bool:
    parent = normalize_filesystem_path(path.parent)
    home = normalize_filesystem_path(Path.home())
    roots = [
        Path.home() / "Downloads",
        Path.home() / "Desktop",
        Path.home() / "AppData" / "Local" / "Temp",
        Path.home() / "AppData" / "Roaming",
        Path.home() / "AppData" / "Local",
    ]
    for env_name in ("TEMP", "TMP"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value))
    system_root = os.environ.get("SystemRoot")
    if system_root:
        roots.append(Path(system_root) / "Temp")
    roots.append(Path(r"C:\Windows\Temp"))

    for root in roots:
        if path_is_under(parent, normalize_filesystem_path(root)):
            return True

    parts = {part.lower() for part in path.parts}
    return bool(home and path_is_under(parent, home) and parts.intersection({"downloads", "desktop"}))


def normalize_filesystem_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(str(path))))


def path_is_under(candidate: str, root: str) -> bool:
    if not candidate or not root:
        return False
    try:
        return os.path.commonpath([candidate, root]) == root
    except ValueError:
        return False


def should_scan_content(path: Path, size: int, file_type: str | None, *, include_source: bool) -> bool:
    suffix = path.suffix.lower()
    if not (0 < size <= MAX_TEXT_SCAN_BYTES):
        return False
    if suffix in TEXT_CONTENT_EXTENSIONS or file_type in {"script-text", "html-text"}:
        return True
    if suffix in SOURCE_CODE_EXTENSIONS:
        return include_source or suffix == ".pyw" or is_risky_location(path) or bool(suspicious_name_hits(path))
    if suffix == ".txt":
        lowered = path.name.lower()
        return any(word in lowered for word in ("script", "command", "install", "setup", "run", "payload"))
    return False


def scan_content_bytes(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for view_name, view in content_scan_views(data):
        detail = "Pattern matched in file content" if view_name == "raw" else f"Pattern matched after {view_name} decoding"
        for finding in scan_content_rule_matches(view, detail):
            if finding.rule_id in seen:
                continue
            seen.add(finding.rule_id)
            findings.append(finding)
    findings.extend(scan_powershell_encoded_payloads(data, seen))
    return findings


def scan_content_rule_matches(data: bytes, detail: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in CONTENT_RULES:
        match = rule.regex.search(data)
        if match:
            if rule.rule_id == "long-base64-blob" and not base64_blob_has_execution_context(data, match.start(), match.end()):
                continue
            findings.append(Finding(rule.rule_id, rule.title, rule.severity, detail, describe_match(data, match.start(), match.end()), rule.remediation))
    return findings


def base64_blob_has_execution_context(data: bytes, start: int, end: int) -> bool:
    window = data[max(0, start - 500) : min(len(data), end + 500)].lower()
    return any(token in window for token in (b"eval", b"iex", b"invoke-expression", b"frombase64string", b"atob", b"base64decode", b"encodedcommand"))


def content_scan_views(data: bytes) -> Iterable[tuple[str, bytes]]:
    yield "raw", data
    yielded = {data}
    for encoding, text in decoded_text_views(data):
        normalized = text.encode("utf-8", errors="replace")
        if normalized in yielded:
            continue
        yielded.add(normalized)
        yield encoding, normalized


def decoded_text_views(data: bytes) -> Iterable[tuple[str, str]]:
    encodings = ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"]
    if data.startswith(b"\xff\xfe"):
        encodings = ["utf-16", "utf-16-le", "utf-8-sig", "utf-16-be"]
    elif data.startswith(b"\xfe\xff"):
        encodings = ["utf-16", "utf-16-be", "utf-8-sig", "utf-16-le"]

    seen: set[str] = set()
    for encoding in encodings:
        try:
            text = data.decode(encoding)
        except UnicodeError:
            continue
        if text in seen or not is_probably_text(text):
            continue
        seen.add(text)
        yield encoding, text


def is_probably_text(text: str) -> bool:
    if not text:
        return False
    sample = text[:4096]
    replacement_count = sample.count("\ufffd")
    if replacement_count > max(1, len(sample) // 100):
        return False
    printable = sum(1 for char in sample if char.isprintable() or char.isspace())
    return printable / len(sample) >= 0.85


def scan_powershell_encoded_payloads(data: bytes, existing_rule_ids: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    payload_pattern = re.compile(r"(?is)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,250}(?<!\w)(?:-enc|-encodedcommand)(?!\w)\s+([A-Za-z0-9+/=]{20,})")
    seen_payloads: set[str] = set()
    for _, text in decoded_text_views(data):
        for match in payload_pattern.finditer(text):
            encoded = match.group(1)
            if encoded in seen_payloads:
                continue
            seen_payloads.add(encoded)
            decoded = decode_powershell_payload(encoded)
            if not decoded:
                continue
            payload_bytes = decoded.encode("utf-8", errors="replace")
            for finding in scan_content_rule_matches(payload_bytes, "Pattern matched in decoded PowerShell -EncodedCommand payload"):
                if finding.rule_id == "ps-encoded-command":
                    continue
                decoded_rule_id = f"decoded-{finding.rule_id}"
                if decoded_rule_id in existing_rule_ids:
                    continue
                existing_rule_ids.add(decoded_rule_id)
                findings.append(
                    Finding(
                        decoded_rule_id,
                        f"Decoded PowerShell payload: {finding.title}",
                        finding.severity,
                        finding.detail,
                        finding.evidence,
                    )
                )
    return findings


def decode_powershell_payload(encoded: str) -> str | None:
    padded = encoded + ("=" * (-len(encoded) % 4))
    try:
        payload = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-16-le", "utf-8", "utf-16-be"):
        try:
            text = payload.decode(encoding)
        except UnicodeError:
            continue
        if is_probably_text(text):
            return text
    return None


def describe_match(data: bytes, start: int, end: int) -> str:
    line = data.count(b"\n", 0, start) + 1
    excerpt_start = max(0, start - 60)
    excerpt_end = min(len(data), end + 90)
    return f"line {line}, byte {start}: {safe_excerpt(data[excerpt_start:excerpt_end])}"


def safe_excerpt(data: bytes, limit: int = 180) -> str:
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"\s+", " ", text).strip()
    text = text.encode("unicode_escape", errors="backslashreplace").decode("ascii", errors="replace")
    if len(text) > limit:
        return f"{text[: limit - 3]}..."
    return text


def scan_basic_document_content(path: Path, sample: bytes, file_type: str | None) -> list[Finding]:
    suffix = path.suffix.lower()
    findings: list[Finding] = []
    if file_type == "pdf-document" or suffix == ".pdf":
        for rule_id, title, pattern in (
            ("pdf-javascript", "PDF contains JavaScript action", rb"(?is)/(?:JavaScript|JS)\b"),
            ("pdf-launch-action", "PDF contains Launch/OpenAction behavior", rb"(?is)/(?:Launch|OpenAction|AA)\b"),
        ):
            match = re.search(pattern, sample)
            if match:
                findings.append(
                    Finding(
                        rule_id,
                        title,
                        "medium",
                        str(path.name),
                        describe_match(sample, match.start(), match.end()),
                        "Open the PDF only in a sandboxed viewer and verify it with a dedicated PDF analysis tool.",
                    )
                )
    if file_type == "compound-document" or suffix in {".doc", ".xls", ".ppt", ".msi"}:
        lowered = sample.lower()
        if b"vba" in lowered or b"macros" in lowered or b"attrib" in lowered:
            findings.append(
                Finding(
                    "legacy-office-macro-indicator",
                    "Legacy Office/OLE file has macro indicators",
                    "medium",
                    str(path.name),
                    None,
                    "Open only with macros disabled and inspect with olevba or an enterprise malware scanner.",
                )
            )
    if file_type == "windows-shortcut" or suffix == ".lnk":
        text = sample.decode("utf-16-le", errors="ignore") + "\n" + sample.decode("latin-1", errors="ignore")
        if re.search(r"(?is)\b(?:powershell|pwsh|mshta|wscript|cscript|rundll32|cmd)(?:\.exe)?\b", text):
            findings.append(
                Finding(
                    "shortcut-suspicious-target",
                    "Shortcut references a suspicious command interpreter",
                    "high",
                    str(path.name),
                    safe_excerpt(text.encode("utf-8", errors="replace")),
                    "Inspect the shortcut target and arguments before opening it.",
                )
            )
    return findings


def scan_unsupported_archive(path: Path, file_type: str | None, sample: bytes) -> list[Finding]:
    suffix = path.suffix.lower()
    findings = [
        Finding(
            "unsupported-archive",
            "Archive format is detected but not deeply inspected",
            "low",
            f"extension={suffix or '(none)'}, detected={file_type or 'unknown'}",
        )
    ]
    if file_type == "self-extracting-archive" or (sample.startswith(b"MZ") and (b"Rar!\x1A\x07" in sample or b"7z\xBC\xAF\x27\x1C" in sample)):
        findings.append(Finding("self-extracting-archive", "Executable contains embedded archive signature", "medium", str(path.name)))
    if suffix in {".iso", ".img"}:
        findings.append(Finding("disk-image-archive", "Disk image can contain hidden executable content", "medium", suffix))
    return findings


def scan_zip(path: Path, *, max_depth: int = 2) -> list[Finding]:
    try:
        with zipfile.ZipFile(path) as archive:
            return scan_zip_archive(archive, max_depth=max_depth)
    except (OSError, zipfile.BadZipFile) as exc:
        return [Finding("bad-zip", "Invalid or damaged zip archive", "low", f"Could not parse as zip: {type(exc).__name__}")]


def scan_zip_archive(archive: zipfile.ZipFile, *, max_depth: int = 2, depth: int = 0) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    infos = archive.infolist()
    total_size = sum(max(info.file_size, 0) for info in infos)
    total_compressed = sum(max(info.compress_size, 0) for info in infos)
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        add_archive_finding(findings, seen, Finding("large-archive", "Archive has many entries", "low", f"{len(infos)} entries; scanned all entry names and selected content candidates"))
    if total_size >= 500 * 1024 * 1024:
        add_archive_finding(findings, seen, Finding("huge-archive", "Archive expands to a very large size", "medium", format_bytes(total_size)))
    if total_compressed and total_size / total_compressed >= 100 and total_size >= 50 * 1024 * 1024:
        ratio = total_size / total_compressed
        add_archive_finding(findings, seen, Finding("zip-bomb-shape", "Archive has a suspicious compression ratio", "high", f"expanded={format_bytes(total_size)}, compressed={format_bytes(total_compressed)}, ratio={ratio:.1f}x"))

    content_candidates: list[tuple[int, zipfile.ZipInfo, str, str]] = []
    for info in infos:
        name = info.filename
        if not name or name.endswith("/"):
            continue
        normalized = name.replace("\\", "/")
        entry_name = PurePosixPath(normalized).name
        suffix = PurePosixPath(normalized).suffix.lower()

        if archive_path_is_unsafe(normalized):
            add_archive_finding(findings, seen, Finding("archive-path-traversal", "Archive entry can escape the destination folder", "high", normalized))

        if suffix in ARCHIVE_HIGH_RISK_EXTENSIONS:
            add_archive_finding(findings, seen, Finding("archive-runnable", "Archive contains high-risk runnable content", "high", normalized))
        elif suffix in DANGEROUS_EXTENSIONS:
            add_archive_finding(findings, seen, Finding("archive-runnable", "Archive contains runnable content", "medium", normalized))
        elif suffix in SOURCE_CODE_EXTENSIONS:
            add_archive_finding(findings, seen, Finding("archive-source-code", "Archive contains source-code script", "low", normalized))

        if is_double_extension(Path(entry_name)):
            add_archive_finding(findings, seen, Finding("archive-double-extension", "Archive contains disguised runnable file", "high", normalized))

        for pattern in suspicious_name_hits_text(normalized):
            add_archive_finding(findings, seen, Finding("archive-suspicious-name", "Archive entry has scam-like name", "medium", f"{normalized}; pattern={pattern}"))

        for detail, severity in suspicious_filename_flags(entry_name):
            add_archive_finding(findings, seen, Finding("archive-suspicious-filename", "Archive entry has suspicious filename characters", severity, f"{normalized}; {detail}"))

        if is_office_macro_entry(normalized):
            add_archive_finding(findings, seen, Finding("office-macro-project", "Office document contains macro project data", "high", normalized))

        if is_office_external_relationship_candidate(normalized, info.file_size):
            content_candidates.append((archive_entry_priority(normalized, suffix, info.file_size), info, normalized, suffix))

        if should_scan_archive_entry_content(normalized, suffix, info.file_size):
            content_candidates.append((archive_entry_priority(normalized, suffix, info.file_size), info, normalized, suffix))
        elif suffix in ZIP_CONTAINER_EXTENSIONS and 0 < info.file_size <= 2_000_000:
            content_candidates.append((archive_entry_priority(normalized, suffix, info.file_size), info, normalized, suffix))

    content_candidates.sort(key=lambda item: item[0])
    for _, info, normalized, suffix in content_candidates[:MAX_ARCHIVE_CONTENT_CANDIDATES]:
        if is_office_external_relationship_candidate(normalized, info.file_size):
            data = read_zip_entry_sample(archive, info, findings, seen, normalized)
            if data is None:
                continue
            for finding in scan_office_relationships(normalized, data):
                add_archive_finding(findings, seen, finding)
        if should_scan_archive_entry_content(normalized, suffix, info.file_size):
            data = read_zip_entry_sample(archive, info, findings, seen, normalized)
            if data is None:
                continue
            for finding in scan_content_bytes(data):
                add_archive_finding(
                    findings,
                    seen,
                    Finding(f"archive-{finding.rule_id}", f"Archive entry: {finding.title}", finding.severity, normalized, finding.evidence, finding.remediation),
                )
        if suffix in ZIP_CONTAINER_EXTENSIONS:
            if depth >= max_depth:
                add_archive_finding(findings, seen, Finding("nested-archive-depth-limit", "Nested archive recursion limit reached", "low", normalized))
                continue
            data = read_zip_entry_sample(archive, info, findings, seen, normalized, limit=2_000_000)
            if data:
                nested_findings = scan_nested_zip_bytes(data, normalized, max_depth=max_depth, depth=depth + 1)
                for finding in nested_findings:
                    add_archive_finding(findings, seen, finding)
    return findings


def archive_entry_priority(name: str, suffix: str, size: int) -> int:
    lowered = name.lower()
    score = 50
    if suffix in ARCHIVE_HIGH_RISK_EXTENSIONS:
        score -= 30
    if suffix in ZIP_CONTAINER_EXTENSIONS:
        score -= 25
    if any(word in lowered for word in ("payload", "setup", "install", "update", "run", "token", "wallet", "password")):
        score -= 15
    if suffix in SOURCE_CODE_EXTENSIONS:
        score += 10
    if size > MAX_ARCHIVE_TEXT_ENTRY_BYTES:
        score += 20
    return score


def scan_nested_zip_bytes(data: bytes, parent_name: str, *, max_depth: int = 2, depth: int = 1) -> list[Finding]:
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as nested:
            return [
                Finding(f"nested-{finding.rule_id}", f"Nested archive: {finding.title}", finding.severity, f"{parent_name}!/{finding.detail}", finding.evidence, finding.remediation)
                for finding in scan_zip_archive(nested, max_depth=max_depth, depth=depth)
            ]
    except (OSError, zipfile.BadZipFile):
        return [Finding("nested-bad-zip", "Nested archive could not be parsed", "low", parent_name)]


def add_archive_finding(findings: list[Finding], seen: set[tuple[str, str, str]], finding: Finding) -> None:
    key = (finding.rule_id, finding.severity, finding.detail)
    if key in seen:
        return
    truncated_key = ("archive-findings-truncated", "low", "too many archive findings")
    if len(findings) >= MAX_ARCHIVE_FINDINGS - 1:
        if truncated_key not in seen:
            seen.add(truncated_key)
            shown = max(0, MAX_ARCHIVE_FINDINGS - 1)
            findings.append(Finding("archive-findings-truncated", "Archive findings were truncated", "low", f"showing first {shown} findings; additional entries omitted"))
        return
    seen.add(key)
    findings.append(finding)


def archive_path_is_unsafe(name: str) -> bool:
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return True
    return any(part == ".." for part in PurePosixPath(name).parts)


def is_office_macro_entry(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith("vbaproject.bin") or "/vba/" in lowered or lowered.endswith("/_vba_project.bin")


def is_office_external_relationship_candidate(name: str, size: int) -> bool:
    lowered = name.lower()
    return lowered.endswith(".rels") and 0 < size <= MAX_ARCHIVE_TEXT_ENTRY_BYTES


def scan_office_relationships(name: str, data: bytes) -> list[Finding]:
    if b"TargetMode" not in data or b"External" not in data:
        return []
    findings: list[Finding] = []
    for match in re.finditer(rb"(?is)\bTarget\s*=\s*['\"]([^'\"]+)['\"]", data):
        target = match.group(1)
        if re.match(rb"(?is)(?:https?://|file:|\\\\)", target):
            detail = f"{name}: external target {safe_excerpt(target, 120)}"
            findings.append(Finding("office-external-link", "Office document references external content", "medium", detail, describe_match(data, match.start(), match.end())))
    return findings


def should_scan_archive_entry_content(name: str, suffix: str, size: int) -> bool:
    if not (0 < size <= MAX_ARCHIVE_TEXT_ENTRY_BYTES):
        return False
    lowered = name.lower()
    if suffix in TEXT_CONTENT_EXTENSIONS:
        return True
    if suffix in SOURCE_CODE_EXTENSIONS and any(word in lowered for word in ("install", "setup", "payload", "run", "update", "token", "wallet")):
        return True
    return suffix == ".txt" and any(word in lowered for word in ("script", "command", "install", "setup", "run", "payload"))


def read_zip_entry_sample(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    findings: list[Finding],
    seen: set[tuple[str, str, str]],
    entry_name: str,
    limit: int = MAX_ARCHIVE_TEXT_ENTRY_BYTES,
) -> bytes | None:
    try:
        with archive.open(info) as handle:
            return handle.read(limit)
    except RuntimeError as exc:
        message = str(exc)
        if "password required" in message.lower() or "encrypted" in message.lower():
            add_archive_finding(findings, seen, Finding("encrypted-archive-entry", "Archive entry is encrypted", "low", entry_name))
        else:
            add_archive_finding(findings, seen, Finding("archive-entry-unreadable", "Archive entry could not be read", "low", f"{entry_name}: {type(exc).__name__}: {message}"))
    except Exception as exc:  # noqa: BLE001 - one bad entry should not fail the archive scan.
        add_archive_finding(findings, seen, Finding("archive-entry-unreadable", "Archive entry could not be read", "low", f"{entry_name}: {type(exc).__name__}: {exc}"))
    return None


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


def estimate_entropy_bytes(data: bytes, limit: int = 262_144) -> float:
    data = data[:limit]
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
    return entropy


def clean_known_bad(summary: ScanSummary, quarantine_dir: Path, *, delete: bool, cleanable_hashes: set[str]) -> list[str]:
    report: list[str] = []
    cleanable_hashes = {item.lower() for item in cleanable_hashes}
    known_bad_paths = [
        Path(result.path)
        for result in summary.results
        if result.kind == "file" and result.sha256 and result.sha256.lower() in cleanable_hashes
    ]
    if not known_bad_paths:
        external_hits = [
            result
            for result in summary.results
            if result.kind == "file"
            and result.sha256
            and any(finding.rule_id == "known-bad-hash" for finding in result.findings)
            and result.sha256.lower() not in cleanable_hashes
        ]
        if external_hits:
            return ["No cleanable known-bad files found to remove. External --known-bad hits require --clean-user-hashes."]
        return ["No cleanable known-bad files found to remove."]

    if platform.system() == "Windows":
        report.extend(stop_known_bad_processes(known_bad_paths, cleanable_hashes))

    for path in known_bad_paths:
        if not path.exists():
            report.append(f"Already gone: {path}")
            continue
        try:
            current_hash, stable = hash_with_stability_check(path)
            current_hash = current_hash.lower()
            if not stable:
                report.append(f"Skipped unstable file, metadata changed while hashing: {path}")
                continue
            latest_hash, latest_stable = hash_with_stability_check(path)
            latest_hash = latest_hash.lower()
            if not latest_stable or latest_hash != current_hash:
                report.append(f"Skipped changed file, hash changed before cleanup: {path}")
                continue
            if latest_hash not in cleanable_hashes:
                report.append(f"Skipped changed file, hash no longer matches known bad: {path}")
                continue
            if delete:
                path.unlink()
                report.append(f"Deleted known-bad file: {path}")
            else:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                destination = unique_quarantine_path(quarantine_dir, path, latest_hash)
                path.replace(destination)
                report.append(f"Quarantined known-bad file: {path} -> {destination}")
        except Exception as exc:  # noqa: BLE001 - cleanup should report each failure.
            report.append(f"Failed to remove {path}: {type(exc).__name__}: {exc}")

    if platform.system() == "Windows":
        report.extend(remove_known_bad_startup_entries(cleanable_hashes))
    return report


def hash_with_stability_check(path: Path) -> tuple[str, bool]:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    stable = (
        before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and getattr(before, "st_ino", 0) == getattr(after, "st_ino", 0)
        and getattr(before, "st_dev", 0) == getattr(after, "st_dev", 0)
    )
    return digest.hexdigest(), stable


def unique_quarantine_path(quarantine_dir: Path, source: Path, sha256_value: str) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source.name)
    base = quarantine_dir / f"{sha256_value[:12]}_{safe_name}.quarantine"
    candidate = base
    counter = 1
    while candidate.exists():
        candidate = quarantine_dir / f"{sha256_value[:12]}_{counter}_{safe_name}.quarantine"
        counter += 1
    return candidate


def stop_known_bad_processes(paths: list[Path], cleanable_hashes: set[str]) -> list[str]:
    report: list[str] = []
    wanted = {str(path.resolve()).lower() for path in paths if path.exists()}
    powershell = trusted_windows_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    taskkill = trusted_windows_executable("taskkill.exe")
    if not powershell:
        return ["Could not inspect running processes: trusted powershell.exe was not found under System32."]
    if not taskkill:
        return ["Could not stop running processes: trusted taskkill.exe was not found under System32."]
    script = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.ExecutablePath } | "
        "ForEach-Object { [Console]::WriteLine(($_.ProcessId.ToString() + '|' + $_.ExecutablePath)) }"
    )
    try:
        completed = subprocess.run([str(powershell), "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=15, check=False)
    except Exception as exc:  # noqa: BLE001
        return [f"Could not inspect running processes: {type(exc).__name__}: {exc}"]

    for line in completed.stdout.splitlines():
        pid_text, _, exe_path = line.partition("|")
        if not pid_text or not exe_path:
            continue
        if exe_path.lower() not in wanted:
            continue
        try:
            if sha256_file(Path(exe_path)).lower() not in cleanable_hashes:
                continue
            subprocess.run([str(taskkill), "/PID", pid_text, "/F"], capture_output=True, text=True, timeout=10, check=False)
            report.append(f"Stopped running known-bad process PID {pid_text}: {exe_path}")
        except Exception as exc:  # noqa: BLE001
            report.append(f"Failed to stop process PID {pid_text}: {type(exc).__name__}: {exc}")
    return report


def remove_known_bad_startup_entries(cleanable_hashes: set[str]) -> list[str]:
    try:
        import winreg
    except ImportError:
        return []

    report: list[str] = []
    run_keys = [
        ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive_name, hive, key_path in run_keys:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                names_to_delete: list[str] = []
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    if startup_value_references_known_bad(str(value), cleanable_hashes):
                        names_to_delete.append(name)
                    index += 1
                for name in names_to_delete:
                    winreg.DeleteValue(key, name)
                    report.append(f"Removed known-bad startup entry: {hive_name}\\{key_path}\\{name}")
        except PermissionError:
            report.append(f"Need administrator rights to clean: {hive_name}\\{key_path}")
        except OSError:
            continue
    return report


def startup_value_references_known_bad(value: str, cleanable_hashes: set[str]) -> bool:
    for candidate in extract_windows_paths(value):
        try:
            path = Path(candidate)
            if path.exists() and sha256_file(path).lower() in cleanable_hashes:
                return True
        except OSError:
            continue
    return False


def extract_windows_paths(value: str) -> list[str]:
    quoted = re.findall(r'"([^"]+\.(?:exe|scr|com|bat|cmd|ps1|vbs|js|msi))"', value, flags=re.IGNORECASE)
    unquoted = re.findall(r"([A-Za-z]:\\[^\s]+?\.(?:exe|scr|com|bat|cmd|ps1|vbs|js|msi))", value, flags=re.IGNORECASE)
    return quoted + unquoted


def trusted_windows_executable(*relative_parts: str) -> Path | None:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(system_root) / "System32"
    for part in relative_parts:
        candidate /= part
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    system32 = (Path(system_root) / "System32").resolve()
    if not path_is_under(normalize_filesystem_path(resolved), normalize_filesystem_path(system32)):
        return None
    return resolved if resolved.exists() else None


def authenticode_status(path: Path) -> tuple[str, str]:
    cache_key = signature_cache_key(path)
    if cache_key and cache_key in AUTHENTICODE_CACHE:
        return AUTHENTICODE_CACHE[cache_key]
    powershell = trusted_windows_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    if not powershell:
        return "UnknownError", "trusted powershell.exe was not found under System32"
    command = [
        str(powershell),
        "-NoProfile",
        "-Command",
        "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "$n=''; if ($s.SignerCertificate) { $n=$s.SignerCertificate.Subject }; "
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8; "
        "Write-Output ($s.Status.ToString() + '|' + $n)",
        str(path),
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    except Exception as exc:  # noqa: BLE001 - signature checking is advisory.
        return "UnknownError", str(exc)
    output = completed.stdout.strip().splitlines()
    if not output:
        return "UnknownError", completed.stderr.strip()
    status, _, signer = output[-1].partition("|")
    result = (status.strip(), signer.strip())
    if cache_key and should_cache_signature_result(path, result[0], result[1]):
        AUTHENTICODE_CACHE[cache_key] = result
    return result


def signature_cache_key(path: Path) -> tuple[str, int, int] | None:
    try:
        info = path.stat()
        return (normalize_filesystem_path(path), int(info.st_mtime_ns), int(info.st_size))
    except OSError:
        return None


def should_cache_signature_result(path: Path, status: str, signer: str) -> bool:
    return status == "Valid" and bool(signer.strip())


def scan_startup_locations() -> list[ScanResult]:
    results: list[ScanResult] = []
    results.extend(scan_startup_folders())
    results.extend(scan_registry_run_keys())
    results.extend(scan_registry_persistence_locations())
    results.extend(scan_scheduled_tasks())
    results.extend(scan_browser_extensions())
    results.extend(scan_wmi_event_consumers())
    return results


def scan_startup_folders() -> list[ScanResult]:
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    paths = []
    if appdata:
        paths.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
    if programdata:
        paths.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\StartUp")

    results: list[ScanResult] = []
    for folder in paths:
        if not folder.exists():
            continue
        for item in folder.glob("*"):
            result = ScanResult(path=str(item), kind="startup")
            result.findings.append(Finding("startup-folder-entry", "File starts automatically at login", "medium", str(folder)))
            results.append(result)
    return results


def scan_registry_run_keys() -> list[ScanResult]:
    try:
        import winreg
    except ImportError:
        return []

    run_keys = [
        ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    results: list[ScanResult] = []
    for hive_name, hive, key_path in run_keys:
        try:
            with winreg.OpenKey(hive, key_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    result = ScanResult(path=f"{hive_name}\\{key_path}\\{name}", kind="registry")
                    severity = "high" if suspicious_startup_command(str(value)) else "medium"
                    result.findings.append(Finding("registry-run-entry", "Registry Run key starts automatically at login", severity, str(value)))
                    results.append(result)
                    index += 1
        except OSError:
            continue
    return results


def scan_registry_persistence_locations() -> list[ScanResult]:
    try:
        import winreg
    except ImportError:
        return []

    checks = [
        (
            "HKEY_LOCAL_MACHINE",
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "ifeo-debugger",
            "Image File Execution Options debugger persistence",
        ),
        (
            "HKEY_CURRENT_USER",
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            "shell-icon-overlay",
            "Shell icon overlay handler loads into Explorer",
        ),
        (
            "HKEY_LOCAL_MACHINE",
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            "shell-icon-overlay",
            "Shell icon overlay handler loads into Explorer",
        ),
    ]
    results: list[ScanResult] = []
    for hive_name, hive, key_path, rule_id, title in checks:
        try:
            with winreg.OpenKey(hive, key_path) as key:
                subkey_index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, subkey_index)
                    except OSError:
                        break
                    subkey_index += 1
                    full_path = f"{hive_name}\\{key_path}\\{subkey_name}"
                    detail = registry_subkey_default_detail(hive, f"{key_path}\\{subkey_name}")
                    severity = "high" if suspicious_startup_command(detail) else "medium"
                    if rule_id == "ifeo-debugger" and "debugger" not in detail.lower():
                        continue
                    result = ScanResult(path=full_path, kind="registry")
                    result.findings.append(Finding(rule_id, title, severity, detail or subkey_name))
                    results.append(result)
        except OSError:
            continue
    return results


def registry_subkey_default_detail(hive: object, key_path: str) -> str:
    try:
        import winreg
    except ImportError:
        return ""
    details: list[str] = []
    try:
        with winreg.OpenKey(hive, key_path) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                if name == "" or name.lower() in {"debugger", "clSID".lower()}:
                    details.append(f"{name or '(default)'}={value}")
                index += 1
    except OSError:
        return ""
    return "; ".join(details)


def scan_scheduled_tasks() -> list[ScanResult]:
    if platform.system() != "Windows":
        return []
    task_root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
    if not task_root.exists():
        return []
    results: list[ScanResult] = []
    stack = [task_root]
    inspected = 0
    while stack and inspected < 5000:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(path)
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        inspected += 1
                        data = path.read_bytes()[:MAX_ARCHIVE_TEXT_ENTRY_BYTES]
                    except OSError:
                        continue
                    text = data.decode("utf-16", errors="ignore") if data.startswith((b"\xff\xfe", b"\xfe\xff")) else data.decode("utf-8", errors="ignore")
                    command = first_xml_text(text, "Command")
                    arguments = first_xml_text(text, "Arguments")
                    if not command and not arguments:
                        continue
                    detail = " ".join(part for part in (command, arguments) if part).strip()
                    relative = path.relative_to(task_root) if path_is_relative_to(path, task_root) else path.name
                    if suspicious_startup_command(detail):
                        result = ScanResult(path=f"scheduled-task:{relative}", kind="scheduled-task")
                        result.findings.append(Finding("scheduled-task-suspicious-action", "Scheduled task runs a suspicious command", "high", detail))
                        results.append(result)
                    elif "microsoft" not in str(relative).lower():
                        result = ScanResult(path=f"scheduled-task:{relative}", kind="scheduled-task")
                        result.findings.append(Finding("scheduled-task-entry", "Non-Microsoft scheduled task starts automatically", "low", detail))
                        results.append(result)
        except OSError:
            continue
    return results


def first_xml_text(text: str, tag: str) -> str:
    match = re.search(rf"(?is)<{re.escape(tag)}>\s*(.*?)\s*</{re.escape(tag)}>", text)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def scan_browser_extensions() -> list[ScanResult]:
    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        return []
    roots = [
        Path(local_appdata) / "Google" / "Chrome" / "User Data",
        Path(local_appdata) / "Microsoft" / "Edge" / "User Data",
        Path(local_appdata) / "BraveSoftware" / "Brave-Browser" / "User Data",
    ]
    results: list[ScanResult] = []
    for user_data in roots:
        if not user_data.exists():
            continue
        for profile in browser_profiles(user_data):
            extension_root = profile / "Extensions"
            if not extension_root.exists():
                continue
            for extension_dir in extension_root.iterdir():
                if not extension_dir.is_dir():
                    continue
                manifest_path = newest_manifest(extension_dir)
                if not manifest_path:
                    continue
                result = analyze_extension_manifest(extension_dir.name, manifest_path)
                if result:
                    results.append(result)
    return results


def browser_profiles(user_data: Path) -> Iterable[Path]:
    for child in user_data.iterdir():
        if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile ")):
            yield child


def newest_manifest(extension_dir: Path) -> Path | None:
    manifests = [path / "manifest.json" for path in extension_dir.iterdir() if path.is_dir() and (path / "manifest.json").exists()]
    manifests.extend([extension_dir / "manifest.json"] if (extension_dir / "manifest.json").exists() else [])
    if not manifests:
        return None
    return max(manifests, key=lambda item: item.stat().st_mtime)


def analyze_extension_manifest(extension_id: str, manifest_path: Path) -> ScanResult | None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    permissions = extension_permissions(manifest)
    risky_permissions = sorted(permissions.intersection({"cookies", "webRequest", "webRequestBlocking", "nativeMessaging", "tabs", "proxy", "downloads", "management", "debugger", "clipboardRead", "scripting"}))
    broad_host_access = any(value in permissions for value in {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"})
    sideloaded = not manifest.get("update_url")
    findings: list[Finding] = []
    if risky_permissions and broad_host_access:
        findings.append(Finding("browser-extension-risky-permissions", "Browser extension has broad and risky permissions", "high", f"id={extension_id}, permissions={', '.join(risky_permissions)}"))
    elif risky_permissions or broad_host_access:
        findings.append(Finding("browser-extension-review", "Browser extension has permissions worth reviewing", "medium", f"id={extension_id}, permissions={', '.join(sorted(permissions))[:300]}"))
    if sideloaded and (risky_permissions or broad_host_access):
        findings.append(Finding("browser-extension-sideloaded", "Browser extension appears sideloaded or locally installed", "medium", f"id={extension_id}, manifest={manifest_path}"))
    if not findings:
        return None
    result = ScanResult(path=str(manifest_path), kind="browser-extension")
    result.findings.extend(findings)
    return result


def extension_permissions(manifest: dict) -> set[str]:
    permissions: set[str] = set()
    for key in ("permissions", "optional_permissions", "host_permissions", "optional_host_permissions"):
        values = manifest.get(key)
        if isinstance(values, list):
            permissions.update(str(value) for value in values)
    for item in manifest.get("content_scripts", []) if isinstance(manifest.get("content_scripts"), list) else []:
        if isinstance(item, dict) and isinstance(item.get("matches"), list):
            permissions.update(str(value) for value in item["matches"])
    externally_connectable = manifest.get("externally_connectable")
    if isinstance(externally_connectable, dict) and isinstance(externally_connectable.get("matches"), list):
        permissions.update(str(value) for value in externally_connectable["matches"])
    return permissions


def scan_wmi_event_consumers() -> list[ScanResult]:
    if platform.system() != "Windows":
        return []
    powershell = trusted_windows_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    if not powershell:
        return []
    script = (
        "$items=@();"
        "Get-WmiObject -Namespace root\\subscription -Class __EventFilter -ErrorAction SilentlyContinue | "
        "ForEach-Object { $items += [pscustomobject]@{Class=$_.__CLASS;Name=$_.Name;Detail=$_.Query} };"
        "Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | "
        "ForEach-Object { $items += [pscustomobject]@{Class=$_.__CLASS;Name=$_.Name;Detail=$_.CommandLineTemplate} };"
        "Get-WmiObject -Namespace root\\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | "
        "ForEach-Object { $items += [pscustomobject]@{Class=$_.__CLASS;Name=$_.Name;Detail=$_.ScriptText} };"
        "$items | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run([str(powershell), "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=12, check=False)
    except Exception:  # noqa: BLE001 - advisory collector only.
        return []
    if not completed.stdout.strip():
        return []
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else [data]
    results: list[ScanResult] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name") or "(unnamed)")
        detail = str(item.get("Detail") or "")
        class_name = str(item.get("Class") or "WMI")
        result = ScanResult(path=f"wmi:{class_name}:{name}", kind="wmi-persistence")
        severity = "high" if suspicious_startup_command(detail) else "medium"
        result.findings.append(Finding("wmi-event-consumer", "WMI subscription persistence exists", severity, detail or class_name))
        results.append(result)
    return results


def suspicious_startup_command(value: str) -> bool:
    lowered = value.lower()
    suspicious_bits = ["powershell", "-enc", "wscript", "cscript", "appdata", "temp", "http://", "https://"]
    return sum(bit in lowered for bit in suspicious_bits) >= 2


if __name__ == "__main__":
    sys.exit(main())
