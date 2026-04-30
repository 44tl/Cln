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
import struct
import subprocess
import sys
import time
import zlib
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
MAX_PDF_OBJECT_SCAN_BYTES = 8_000_000
MAX_STRUCTURED_TEXT_BYTES = 2_000_000
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

BUILTIN_KNOWN_BAD_FILENAMES = {
    "7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab": {
        "lnstailer.exe",
        "lnstaier.exe",
        "lnstaler.exe",
        "lnstaiier.exe",
        "lnstaier",
    },
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

SUSPICIOUS_PE_SECTION_NAMES = {
    ".aspack",
    ".adata",
    ".boom",
    ".ccg",
    ".enigma",
    ".fsg",
    ".mackt",
    ".mpress",
    ".nsp",
    ".packed",
    ".petite",
    ".pklstb",
    ".rmnet",
    ".svkp",
    ".themida",
    ".upx",
    ".upx0",
    ".upx1",
    ".vmp",
    ".vmp0",
    ".vmp1",
    ".winapi",
    ".yoda",
}

HIGH_RISK_IMPORTS = {
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "rtlcreateuserthread",
    "setwindowshookex",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopenurla",
    "internetopenurlw",
    "winexec",
    "shellexecutea",
    "shellexecutew",
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
        existing = {rule.rule_id for rule in self.rules}
        for rule in rules:
            if rule.rule_id in existing:
                continue
            self.rules.append(rule)
            existing.add(rule.rule_id)

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

RULE_PACK_CHOICES = ("recommended", "downloads", "scripts", "documents", "full")
RULE_PACK_DESCRIPTIONS = {
    "recommended": "Recommended: balanced local rules for scams, scripts, documents, archives, and startup risk.",
    "downloads": "Downloads: stronger scam, fake installer, archive, and renamed executable checks.",
    "scripts": "Scripts: stronger PowerShell, batch, JavaScript, VBScript, and credential theft checks.",
    "documents": "Documents: stronger Office, PDF, macro, and external-link checks.",
    "full": "Full: all built-in rule packs with more review noise.",
}

SUSPICIOUS_NETWORK_PORTS = {1337, 4444, 5555, 6666, 8080, 8443, 31337}

BUILTIN_RULE_PACK_RULES: dict[str, list[ContentRule]] = {
    "downloads": [
        ContentRule("pack-download-suspicious-installer", "Downloaded installer uses scam or lure language", "high", re.compile(rb"(?is)(?:setup|installer|update).{0,180}(?:free|gift|nitro|robux|wallet|verify|airdrop|crack|keygen)"), "Do not run the installer until the publisher and download source are verified."),
        ContentRule("pack-download-password-archive", "Download references password-protected archive behavior", "medium", re.compile(rb"(?is)(?:password|passcode).{0,120}(?:zip|rar|7z|archive)|(?:zip|rar|7z|archive).{0,120}(?:password|passcode)"), "Password-protected archives often bypass attachment scanning; inspect contents carefully."),
    ],
    "scripts": [
        ContentRule("pack-script-hidden-window", "Script launches a hidden process window", "high", re.compile(rb"(?is)(?:-windowstyle\s+hidden|wscript\.shell.{0,120}run.{0,120},\s*0\b|start-process.{0,180}-windowstyle\s+hidden)"), "Hidden script execution is high-risk unless expected from a trusted admin tool."),
        ContentRule("pack-script-clipboard-or-token-access", "Script references clipboard or token data", "medium", re.compile(rb"(?is)(?:Get-Clipboard|navigator\.clipboard|clipboardData|discord.{0,80}token|authorization.{0,40}bearer)"), "Review whether the script collects credentials, tokens, or clipboard contents."),
    ],
    "documents": [
        ContentRule("pack-doc-office-dde", "Office document content references DDE execution", "high", re.compile(rb"(?is)\bDDE(?:AUTO)?\b.{0,180}\b(?:cmd|powershell|mshta|rundll32|wscript)"), "Open only with macros and external content disabled, then inspect the document."),
        ContentRule("pack-doc-pdf-submitform", "PDF references form submission behavior", "medium", re.compile(rb"(?is)/(?:SubmitForm|GoToE|RichMedia|AcroForm)\b"), "Review the PDF actions in a sandboxed viewer."),
    ],
}

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
    confidence: str | None = None
    signals: list[str] = field(default_factory=list)
    false_positive_notes: str | None = None
    next_action: str | None = None
    related: list[str] = field(default_factory=list)


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


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)


@dataclass
class PEInfo:
    machine: int = 0
    timestamp: int = 0
    is_pe64: bool = False
    entry_point_rva: int = 0
    image_base: int = 0
    import_table_rva: int = 0
    import_table_size: int = 0
    export_table_rva: int = 0
    export_table_size: int = 0
    resource_table_rva: int = 0
    resource_table_size: int = 0
    tls_table_rva: int = 0
    tls_table_size: int = 0
    debug_table_rva: int = 0
    debug_table_size: int = 0
    sections: list[PESection] = field(default_factory=list)
    imports: list[tuple[str, str]] = field(default_factory=list)


def finding_to_dict(finding: Finding, *, redact: bool | str = True) -> dict[str, object]:
    finding = explain_finding(finding)
    return {
        "rule_id": output_text(finding.rule_id, redact=redact),
        "title": output_text(finding.title, redact=redact),
        "severity": output_text(finding.severity, redact=redact),
        "detail": output_text(finding.detail, redact=redact),
        "evidence": output_text(finding.evidence, redact=redact) if finding.evidence else None,
        "remediation": output_text(finding.remediation, redact=redact) if finding.remediation else None,
        "confidence": output_text(finding.confidence, redact=redact) if finding.confidence else None,
        "signals": [output_text(signal, redact=redact) for signal in finding.signals],
        "false_positive_notes": output_text(finding.false_positive_notes, redact=redact) if finding.false_positive_notes else None,
        "next_action": output_text(finding.next_action, redact=redact) if finding.next_action else None,
        "related": [output_text(item, redact=redact) for item in finding.related],
    }


RULE_EXPLANATIONS: dict[str, dict[str, object]] = {
    "known-bad-hash": {
        "confidence": "high",
        "signals": ["Exact SHA-256 hash match"],
        "false_positive_notes": "False positives are unlikely for a confirmed hash, but verify the hash source.",
        "next_action": "Quarantine or delete after confirming the file path and hash.",
    },
    "ps-encoded-command": {
        "confidence": "high",
        "signals": ["PowerShell command line contains -EncodedCommand"],
        "false_positive_notes": "Some administration tools encode commands, but downloaded scripts should be treated carefully.",
        "next_action": "Decode the payload and review network, persistence, and execution behavior.",
    },
    "decoded-ps-download-exec": {
        "confidence": "high",
        "signals": ["Decoded PowerShell payload downloads and executes content"],
        "next_action": "Treat as suspicious until the URL and payload are verified.",
        "related": ["ps-encoded-command", "ps-download-exec"],
    },
    "shortcut-suspicious-target": {
        "confidence": "high",
        "signals": ["Parsed LNK command launches a script interpreter or LOLBin"],
        "false_positive_notes": "Enterprise shortcuts can wrap command interpreters, but consumer downloads rarely should.",
        "next_action": "Inspect the parsed target, arguments, working directory, and icon path before opening.",
    },
    "pdf-open-action": {
        "confidence": "medium",
        "signals": ["PDF object graph contains /OpenAction"],
        "false_positive_notes": "Some benign PDFs use open actions for navigation.",
        "next_action": "Open only in a sandboxed viewer and inspect actions before trusting.",
    },
    "pe-injection-imports": {
        "confidence": "medium",
        "signals": ["PE imports a process injection API cluster"],
        "false_positive_notes": "Debuggers, security tools, and installers can import these APIs legitimately.",
        "next_action": "Combine with signature, location, entropy, and timestamp signals before cleanup.",
    },
}


def explain_finding(finding: Finding) -> Finding:
    if finding.confidence and finding.signals and finding.next_action:
        return finding
    explanation = RULE_EXPLANATIONS.get(finding.rule_id)
    if not explanation:
        base_confidence = "high" if finding.severity in {"critical", "high"} else "medium" if finding.severity == "medium" else "low"
        if finding.confidence is None:
            finding.confidence = base_confidence
        if not finding.signals:
            finding.signals = [finding.title]
        if finding.next_action is None:
            finding.next_action = finding.remediation or "Review the evidence and verify the file source."
        return finding
    if finding.confidence is None:
        finding.confidence = str(explanation.get("confidence") or "medium")
    if not finding.signals:
        finding.signals = [str(item) for item in explanation.get("signals", [])]
    if finding.false_positive_notes is None and explanation.get("false_positive_notes"):
        finding.false_positive_notes = str(explanation["false_positive_notes"])
    if finding.next_action is None and explanation.get("next_action"):
        finding.next_action = str(explanation["next_action"])
    if not finding.related and explanation.get("related"):
        finding.related = [str(item) for item in explanation.get("related", [])]
    return finding


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
                result.findings.extend(analyze_pe_file(path, sample, result.size or len(sample), info.st_mtime))

            if self.check_signatures and (suffix in SIGNED_APP_EXTENSIONS or result.file_type == "windows-pe"):
                self.scan_signature(path, result)
            if suffix == ".lnk" or result.file_type == "windows-shortcut":
                result.findings.extend(scan_lnk(path, sample))
            if suffix == ".pdf" or result.file_type == "pdf-document":
                result.findings.extend(scan_pdf(path, sample))
            if result.file_type in {"windows-pe", "mz-executable"}:
                result.findings.extend(scan_pe(path, sample))
            if result.file_type == "compound-document" or suffix in {".doc", ".xls", ".ppt", ".msi"}:
                result.findings.extend(scan_ole_vba(path, sample))
            if suffix in {".ps1", ".psm1"} or (result.file_type == "script-text" and b"powershell" in sample[:200].lower()):
                result.findings.extend(scan_powershell_ast(path, sample))
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
    parser.add_argument("--profile", choices=("fast", "deep", "forensic", "paranoid"), default="fast", help="Preset scan profile. Explicit flags still override the preset. Default: fast.")
    parser.add_argument("--startup", action="store_true", help="Inspect Windows startup folders and registry Run keys.")
    parser.add_argument("--processes", action="store_true", help="Inspect running process command lines and executable memory regions on Windows.")
    parser.add_argument("--network", action="store_true", help="Map active local network connections to processes on Windows without external lookups.")
    parser.add_argument("--continuous", action="store_true", help="Run a bounded polling scan loop instead of a single scan.")
    parser.add_argument("--poll-interval", type=positive_int, default=30, help="Seconds between --continuous polling rounds. Default: 30.")
    parser.add_argument("--poll-count", type=positive_int, default=3, help="Number of --continuous polling rounds. Default: 3.")
    parser.add_argument("--gui", action="store_true", help="Open the built-in review and removal GUI after scanning.")
    parser.add_argument("--cli", action="store_true", help="Run the command-line scanner instead of the default GUI launcher.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--csv", action="store_true", help="Print findings as CSV.")
    parser.add_argument("--sarif", type=Path, help="Write a SARIF 2.1.0 report for code-scanning or CI ingestion.")
    parser.add_argument("--timeline", action="store_true", help="Include a chronological timeline in JSON and text reports.")
    parser.add_argument("--bundle", type=Path, help="Export a local evidence bundle folder with reports, metadata, hashes, and selected samples.")
    parser.add_argument("--baseline", type=Path, help="Compare against a previous CLN JSON report and only keep new matching findings.")
    parser.add_argument("--rule-pack", choices=RULE_PACK_CHOICES, default="recommended", help="Built-in rule pack for non-technical scanning. Default: recommended.")
    parser.add_argument("--rules", type=Path, help="Load extra content rules from a structured JSON rule file.")
    parser.add_argument("--yara-rules", type=Path, help="Run optional yara-python rules from this file or directory when yara-python is installed.")
    parser.add_argument("--yara-lite-rules", type=Path, help="Run CLN's built-in YARA-lite JSON rule engine.")
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
    parser.add_argument("--restore", type=Path, help="Restore a quarantined file using a CLN quarantine manifest.")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"), help="Where readable text reports are saved. Default: .\\reports")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.json and args.csv:
        parser.error("--json and --csv cannot be used together")
    if should_launch_default_gui(args, argv):
        launch_settings_gui(args)
        return 0
    apply_profile_defaults(args)
    global COLOR_ENABLED
    if args.no_color or args.json or args.csv or args.gui:
        COLOR_ENABLED = False
    redact_outputs = "none" if args.no_redact else args.redact_level
    if args.restore:
        report = restore_quarantine_manifest(args.restore)
        if args.json:
            print(json.dumps({"restore": [output_text(line, redact=redact_outputs) for line in report]}, indent=2))
        else:
            for line in report:
                print(output_text(line, redact=redact_outputs))
        return 0 if report and report[0].startswith("Restored") else 1
    paths = choose_paths(args)
    verbose = not args.quiet and not args.json and not args.csv and not args.gui
    user_known_bad = load_hashes(args.known_bad)
    CONTENT_RULES.extend(load_builtin_rule_pack(args.rule_pack))
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
    summary = run_continuous_scan(scanner, paths, args.poll_interval, args.poll_count, verbose=verbose) if args.continuous else scanner.scan_paths(paths)
    if args.yara_rules:
        apply_yara_rules(summary, args.yara_rules)
    if args.yara_lite_rules:
        apply_yara_lite_rules(summary, args.yara_lite_rules)
    if args.startup:
        if verbose:
            say("Startup", "Checking folders, registry persistence, tasks, WMI, and browser extensions", "cyan")
        startup_results = scan_startup_locations()
        summary.results.extend(startup_results)
        summary.results.sort(key=lambda item: (-item.score, item.path.lower()))
    if args.processes:
        if verbose:
            say("Processes", "Checking command lines and executable private memory regions", "cyan")
        summary.results.extend(scan_running_processes())
        summary.results.sort(key=lambda item: (-item.score, item.path.lower()))
    if args.network:
        if verbose:
            say("Network", "Mapping active local connections to processes without reputation lookups", "cyan")
        summary.results.extend(scan_network_connections())
        summary.results.sort(key=lambda item: (-item.score, item.path.lower()))

    cleanup_report: list[str] = []
    if args.clean:
        cleanup_report = clean_known_bad(summary, args.quarantine_dir, delete=args.delete, cleanable_hashes=cleanable_hashes)

    if args.baseline:
        summary = filter_baseline(summary, args.baseline, redact=redact_outputs)

    if args.gui:
        launch_removal_gui(summary, paths, args.quarantine_dir, cleanable_hashes, redact=redact_outputs)
        return 0

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
        if args.timeline:
            data["timeline"] = timeline_to_dict(build_timeline(summary), redact=redact_outputs)
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
    if args.bundle:
        try:
            bundle_path = export_evidence_bundle(args.bundle, summary, paths, cleanup_report, redact=redact_outputs)
            if not args.json and not args.csv:
                print(color(f"Evidence bundle: {output_text(bundle_path, redact=redact_outputs)}", "green"))
        except Exception as exc:  # noqa: BLE001
            if not args.json and not args.csv:
                print(color(f"Bundle warning: {type(exc).__name__}: {output_text(exc, redact=redact_outputs)}", "yellow"))
    return 2 if any(result.verdict in {"dangerous", "suspicious"} for result in summary.results) else 0


def should_launch_default_gui(args: argparse.Namespace, argv: list[str] | None) -> bool:
    raw_args = sys.argv[1:] if argv is None else argv
    if args.cli or args.gui or args.json or args.csv or args.sarif or args.clean or args.restore:
        return False
    return len(raw_args) == 0


def powershell_quote(value: object) -> str:
    text = str(value)
    return "'" + text.replace("'", "''") + "'"


def launch_cli_powershell(extra_args: list[str] | None = None) -> None:
    script = Path(__file__).resolve()
    python_exe = Path(sys.executable).resolve()
    args = ["--cli"] + (extra_args or [])
    command = " ".join([powershell_quote(python_exe), powershell_quote(script), *[powershell_quote(item) for item in args]])
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or "powershell.exe"
    subprocess.Popen([powershell, "-NoExit", "-Command", f"& {command}"], close_fds=True)  # noqa: S603 - explicit user action.


def launch_settings_gui(args: argparse.Namespace) -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as exc:  # noqa: BLE001
        print(f"Could not open GUI: {type(exc).__name__}: {exc}")
        print("Run `python cln.py --cli` for the command-line scanner.")
        return

    root = tk.Tk()
    root.title("CLN Scanner")
    root.geometry("980x760")

    container = ttk.Frame(root, padding=10)
    container.pack(fill="both", expand=True)
    canvas = tk.Canvas(container, highlightthickness=0)
    scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    form = ttk.Frame(canvas)
    form.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
    form_window = canvas.create_window((0, 0), window=form, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def sync_form_width(event: object) -> None:
        width = getattr(event, "width", 0)
        if width:
            canvas.itemconfigure(form_window, width=width)

    def scroll_settings(event: object) -> str:
        delta = getattr(event, "delta", 0)
        number = getattr(event, "num", None)
        if delta:
            canvas.yview_scroll(int(-1 * (delta / 120)), "units")
        elif number == 4:
            canvas.yview_scroll(-3, "units")
        elif number == 5:
            canvas.yview_scroll(3, "units")
        return "break"

    def bind_settings_scroll(_: object | None = None) -> None:
        canvas.bind_all("<MouseWheel>", scroll_settings)
        canvas.bind_all("<Button-4>", scroll_settings)
        canvas.bind_all("<Button-5>", scroll_settings)

    def unbind_settings_scroll(_: object | None = None) -> None:
        canvas.unbind_all("<MouseWheel>")
        canvas.unbind_all("<Button-4>")
        canvas.unbind_all("<Button-5>")

    canvas.bind("<Configure>", sync_form_width)
    canvas.bind("<Enter>", bind_settings_scroll)
    canvas.bind("<Leave>", unbind_settings_scroll)

    status_var = tk.StringVar(value="Ready")
    row = 0

    def label(text: str) -> None:
        nonlocal row
        ttk.Label(form, text=text).grid(row=row, column=0, columnspan=4, sticky="w", pady=(12, 4))
        row += 1

    def add_entry(name: str, default: str = "", width: int = 58) -> tk.StringVar:
        nonlocal row
        var = tk.StringVar(value=default)
        ttk.Label(form, text=name).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
        ttk.Entry(form, textvariable=var, width=width).grid(row=row, column=1, columnspan=2, sticky="ew", pady=2)
        row += 1
        return var

    def add_path(name: str, default: str = "", *, directory: bool = False) -> tk.StringVar:
        nonlocal row
        var = tk.StringVar(value=default)
        ttk.Label(form, text=name).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
        ttk.Entry(form, textvariable=var, width=58).grid(row=row, column=1, sticky="ew", pady=2)
        def browse() -> None:
            selected = filedialog.askdirectory() if directory else filedialog.askopenfilename()
            if selected:
                var.set(selected)
        ttk.Button(form, text="Browse", command=browse).grid(row=row, column=2, sticky="w", padx=(6, 0), pady=2)
        row += 1
        return var

    def add_bool(name: str, default: bool = False, tooltip: str = "") -> tk.BooleanVar:
        nonlocal row
        var = tk.BooleanVar(value=default)
        frame = ttk.Frame(form)
        frame.grid(row=row, column=0, columnspan=3, sticky="w", pady=2)
        ttk.Checkbutton(frame, text=name, variable=var).pack(side="left")
        if tooltip:
            info_btn = ttk.Label(frame, text="ⓘ", font=("Segoe UI", 9), foreground="#0066cc", cursor="question_arrow")
            info_btn.pack(side="left", padx=(4, 0))
            tooltip_window = None

            def show_tooltip(event: object | None = None) -> None:
                nonlocal tooltip_window
                if tooltip_window or not tooltip:
                    return
                tooltip_window = tk.Toplevel(root)
                tooltip_window.overrideredirect(True)
                tooltip_window.configure(background="#ffffd0")
                x = info_btn.winfo_rootx()
                y = info_btn.winfo_rooty() + info_btn.winfo_height()
                tooltip_window.geometry(f"+{x}+{y}")
                label = tk.Label(
                    tooltip_window,
                    text=tooltip,
                    font=("Segoe UI", 8),
                    background="#ffffd0",
                    foreground="#000000",
                    relief="solid",
                    borderwidth=1,
                    wraplength=320,
                    justify="left",
                    padx=6,
                    pady=4,
                )
                label.pack()

            def hide_tooltip(event: object | None = None) -> None:
                nonlocal tooltip_window
                if tooltip_window:
                    tooltip_window.destroy()
                    tooltip_window = None

            info_btn.bind("<Enter>", show_tooltip)
            info_btn.bind("<Leave>", hide_tooltip)
        row += 1
        return var

    label("Targets")
    paths_var = add_entry("Paths", "")
    target_buttons = ttk.Frame(form)
    target_buttons.grid(row=row, column=1, columnspan=2, sticky="w", pady=(0, 6))

    def current_targets() -> list[str]:
        return [item.strip() for item in paths_var.get().split(";") if item.strip()]

    def set_targets(values: Iterable[object]) -> None:
        seen: set[str] = set()
        cleaned: list[str] = []
        for value in values:
            text = str(value).strip()
            if not text or text.lower() in seen:
                continue
            seen.add(text.lower())
            cleaned.append(text)
        paths_var.set("; ".join(cleaned))

    def append_targets(values: Iterable[object]) -> None:
        set_targets([*current_targets(), *values])

    def add_files() -> None:
        selected = filedialog.askopenfilenames(title="Select files to scan")
        if selected:
            append_targets(selected)

    def add_folder() -> None:
        selected = filedialog.askdirectory(title="Select folder to scan")
        if selected:
            append_targets([selected])

    def add_common_locations() -> None:
        append_targets(default_quick_paths())

    def choose_drives(*, removable_only: bool) -> None:
        drives = available_scan_drives(removable_only=removable_only)
        if not drives:
            messagebox.showinfo("CLN Scanner", "No matching drives were found.")
            return
        dialog = tk.Toplevel(root)
        dialog.title("Select drives to scan")
        dialog.transient(root)
        dialog.grab_set()
        vars_by_drive: list[tuple[Path, tk.BooleanVar]] = []
        ttk.Label(dialog, text="Select drives to add as scan targets.", padding=10).pack(anchor="w")
        body = ttk.Frame(dialog, padding=(10, 0, 10, 10))
        body.pack(fill="both", expand=True)
        for drive in drives:
            var = tk.BooleanVar(value=True)
            vars_by_drive.append((drive, var))
            ttk.Checkbutton(body, text=str(drive), variable=var).pack(anchor="w", pady=2)
        buttons_frame = ttk.Frame(dialog, padding=10)
        buttons_frame.pack(fill="x")

        def add_selected_drives() -> None:
            append_targets([drive for drive, var in vars_by_drive if var.get()])
            dialog.destroy()

        ttk.Button(buttons_frame, text="Add Selected", command=add_selected_drives).pack(side="right", padx=(8, 0))
        ttk.Button(buttons_frame, text="Cancel", command=dialog.destroy).pack(side="right")

    ttk.Button(target_buttons, text="Add Files", command=add_files).pack(side="left", padx=(0, 6))
    ttk.Button(target_buttons, text="Add Folder", command=add_folder).pack(side="left", padx=(0, 6))
    ttk.Button(target_buttons, text="Add Drive", command=lambda: choose_drives(removable_only=False)).pack(side="left", padx=(0, 6))
    ttk.Button(target_buttons, text="Add USB", command=lambda: choose_drives(removable_only=True)).pack(side="left", padx=(0, 6))
    ttk.Button(target_buttons, text="Common Locations", command=add_common_locations).pack(side="left", padx=(0, 6))
    ttk.Button(target_buttons, text="Clear", command=lambda: paths_var.set("")).pack(side="left")
    row += 1
    full_var = add_bool("Scan whole user profile (--full)", bool(args.full), "Scan everything in your user profile folder (~). Covers Downloads, Desktop, Documents, AppData, and all subfolders.")
    profile_var = tk.StringVar(value=args.profile)
    ttk.Label(form, text="Profile").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
    ttk.Combobox(form, textvariable=profile_var, values=("fast", "deep", "forensic", "paranoid"), state="readonly", width=18).grid(row=row, column=1, sticky="w", pady=2)
    row += 1
    rule_pack_var = tk.StringVar(value=args.rule_pack)
    ttk.Label(form, text="Premade rules").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
    rule_pack_box = ttk.Combobox(form, textvariable=rule_pack_var, values=RULE_PACK_CHOICES, state="readonly", width=18)
    rule_pack_box.grid(row=row, column=1, sticky="w", pady=2)
    rule_pack_help = tk.StringVar(value=RULE_PACK_DESCRIPTIONS[args.rule_pack])
    ttk.Label(form, textvariable=rule_pack_help, wraplength=520).grid(row=row, column=2, sticky="w", padx=(8, 0), pady=2)
    row += 1

    def update_rule_pack_help(*_: object) -> None:
        rule_pack_help.set(RULE_PACK_DESCRIPTIONS.get(rule_pack_var.get(), "Built-in rule pack."))

    rule_pack_box.bind("<<ComboboxSelected>>", update_rule_pack_help)

    label("Scan Coverage")
    startup_var = add_bool("Startup checks (--startup)", bool(args.startup), "Check Windows startup folders, registry Run/RunOnce, COM overrides, IFEO debugger keys, AppInit DLLs, Scheduled Tasks, WMI subscriptions, and risky browser extensions.")
    processes_var = add_bool("Process checks (--processes)", bool(args.processes), "Check running process command lines for living-off-the-land tools (powershell, cmd, regsvr32, rundll32, mshta, etc.) and scan process memory for executable private regions like RWX pages.")
    network_var = add_bool("Network-local telemetry (--network)", bool(args.network), "Map active local network connections to processes and show which executable handles each connection.")
    signatures_var = add_bool("Authenticode signature checks (--signatures)", bool(args.signatures), "Verify Windows executable signatures. Checks if files are signed by trusted publishers and displays certificate chain.")
    source_var = add_bool("Include source-code files (--include-source)", bool(args.include_source), "Also scan script files outside typical risky locations (not just Downloads, Desktop, Documents, temp).")
    no_archives_var = add_bool("Do not inspect archives (--no-archives)", bool(args.no_archives), "Skip scanning inside ZIP, Office, Jar, and other archive files. Faster but may miss threats packed inside archives.")
    timeline_var = add_bool("Include timeline (--timeline)", bool(args.timeline), "Add timestamp-based timeline of file changes to JSON output. Useful for incident response and tracing activity.")

    label("Limits")
    max_mb_var = add_entry("Max MB", str(args.max_mb), width=12)
    workers_var = add_entry("Workers", "" if args.workers is None else str(args.workers), width=12)
    archive_depth_var = add_entry("Archive depth", str(args.archive_depth), width=12)
    recent_days_var = add_entry("Recent days", str(args.recent_days), width=12)
    continuous_var = add_bool("Continuous polling (--continuous)", bool(args.continuous), "Run multiple scans at intervals to catch files that appear briefly or change over time.")
    poll_interval_var = add_entry("Poll interval", str(args.poll_interval), width=12)
    poll_count_var = add_entry("Poll count", str(args.poll_count), width=12)

    label("Rules And Hashes")
    known_bad_var = add_path("Known bad JSON", str(args.known_bad or ""))
    known_good_var = add_path("Known good JSON", str(args.known_good or ""))
    rules_var = add_path("Content rules JSON", str(args.rules or ""))
    yara_var = add_path("YARA rules", str(args.yara_rules or ""))
    yara_lite_var = add_path("YARA-lite rules", str(args.yara_lite_rules or ""))
    baseline_var = add_path("Baseline JSON", str(args.baseline or ""))

    label("Output")
    report_dir_var = add_path("Report directory", str(args.report_dir), directory=True)
    quarantine_dir_var = add_path("Quarantine directory", str(args.quarantine_dir), directory=True)
    bundle_var = add_path("Evidence bundle directory", str(args.bundle or ""), directory=True)
    sarif_var = add_path("SARIF path", str(args.sarif or ""))
    redact_var = tk.StringVar(value=args.redact_level)
    ttk.Label(form, text="Redaction").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
    ttk.Combobox(form, textvariable=redact_var, values=tuple(sorted(REDACTION_LEVELS)), state="readonly", width=18).grid(row=row, column=1, sticky="w", pady=2)
    row += 1
    no_redact_var = add_bool("No redaction (--no-redact)", bool(args.no_redact), "Disable redaction.Shows raw paths and tokens. Use for forensics where evidence must be preserved exactly as found.")
    quiet_var = add_bool("Quiet CLI output (--quiet)", bool(args.quiet), "Suppress terminal progress output. Use when you only need JSON/CSV results or redirect output.")
    no_color_var = add_bool("No CLI color (--no-color)", bool(args.no_color), "Disable colored terminal output. Useful when redirecting to files or using non-UTF8 terminals.")
    json_var = add_bool("JSON CLI output (--json)", bool(args.json), "Output results as JSON for tool integration or automation.")
    csv_var = add_bool("CSV CLI output (--csv)", bool(args.csv), "Output results as CSV for spreadsheet review.")

    label("Cleanup")
    clean_var = add_bool("Clean known-bad files (--clean)", bool(args.clean), "Quarantine files matching built-in known-bad SHA-256 hashes. Requires hash verification before removal.")
    clean_user_var = add_bool("Clean user supplied known-bad hashes (--clean-user-hashes)", bool(args.clean_user_hashes), "Also quarantine files matching hashes from --known-bad. Off by default - must opt in.")
    delete_var = add_bool("Permanent delete instead of quarantine (--delete)", bool(args.delete), "Permanently delete instead of moving to quarantine. Cannot be undone. Use with caution.")
    restore_var = add_path("Restore manifest", str(args.restore or ""))

    def build_args(*, for_gui: bool) -> list[str]:
        built: list[str] = ["--cli"] if not for_gui else ["--gui"]
        for item in paths_var.get().split(";"):
            item = item.strip()
            if item:
                built.append(item)
        bools = [
            (full_var, "--full"),
            (startup_var, "--startup"),
            (processes_var, "--processes"),
            (network_var, "--network"),
            (continuous_var, "--continuous"),
            (timeline_var, "--timeline"),
            (no_archives_var, "--no-archives"),
            (signatures_var, "--signatures"),
            (source_var, "--include-source"),
            (quiet_var, "--quiet"),
            (no_color_var, "--no-color"),
            (no_redact_var, "--no-redact"),
            (clean_var, "--clean"),
            (clean_user_var, "--clean-user-hashes"),
            (delete_var, "--delete"),
        ]
        for var, flag in bools:
            if var.get():
                built.append(flag)
        for flag, var in (
            ("--profile", profile_var),
            ("--rule-pack", rule_pack_var),
            ("--max-mb", max_mb_var),
            ("--archive-depth", archive_depth_var),
            ("--recent-days", recent_days_var),
            ("--poll-interval", poll_interval_var),
            ("--poll-count", poll_count_var),
            ("--redact-level", redact_var),
        ):
            value = var.get().strip()
            if value:
                built.extend([flag, value])
        if workers_var.get().strip():
            built.extend(["--workers", workers_var.get().strip()])
        for flag, var in (
            ("--known-bad", known_bad_var),
            ("--known-good", known_good_var),
            ("--rules", rules_var),
            ("--yara-rules", yara_var),
            ("--yara-lite-rules", yara_lite_var),
            ("--baseline", baseline_var),
            ("--report-dir", report_dir_var),
            ("--quarantine-dir", quarantine_dir_var),
            ("--bundle", bundle_var),
            ("--sarif", sarif_var),
        ):
            value = var.get().strip()
            if value:
                built.extend([flag, value])
        if restore_var.get().strip():
            built.extend(["--restore", restore_var.get().strip()])
        if not for_gui:
            if json_var.get():
                built.append("--json")
            if csv_var.get():
                built.append("--csv")
        return built

    def run_gui_scan() -> None:
        if json_var.get() or csv_var.get():
            messagebox.showinfo("CLN Scanner", "JSON and CSV are CLI output modes. The GUI scan will ignore those two output toggles.")
        root.destroy()
        main(build_args(for_gui=True))

    def close_and_launch_cli() -> None:
        if not messagebox.askyesno("Close and launch as CLI?", "This will close the GUI and launch a powershell CLI version of the tool, are you sure?"):
            return
        cli_args = build_args(for_gui=False)
        root.destroy()
        launch_cli_powershell(cli_args[1:] if cli_args and cli_args[0] == "--cli" else cli_args)

    def show_information() -> None:
        info = tk.Toplevel(root)
        info.title("CLN Scanner Information")
        info.geometry("760x640")
        info.transient(root)
        frame = ttk.Frame(info, padding=10)
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, wrap="word", height=24)
        info_scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=info_scroll.set)
        text.pack(side="left", fill="both", expand=True)
        info_scroll.pack(side="right", fill="y")
        text.insert("end", settings_gui_information_text())
        text.configure(state="disabled")
        buttons_frame = ttk.Frame(info, padding=(10, 0, 10, 10))
        buttons_frame.pack(fill="x")
        ttk.Button(buttons_frame, text="Close", command=info.destroy).pack(side="right")

    action_bar = ttk.Frame(root, padding=(10, 8))
    action_bar.pack(fill="x")
    ttk.Label(action_bar, textvariable=status_var).pack(side="left")
    ttk.Button(action_bar, text="Run Scan", command=run_gui_scan).pack(side="right", padx=(8, 0))
    ttk.Button(action_bar, text="Close and launch as CLI?", command=close_and_launch_cli).pack(side="right", padx=(8, 0))
    ttk.Button(action_bar, text="Close", command=root.destroy).pack(side="right")
    root.mainloop()


def settings_gui_information_text() -> str:
    return (
        "CLN Scanner information\n"
        "\n"
        "What this tool does\n"
        "CLN looks for warning signs in files, shortcuts, scripts, archives, documents, startup items, processes, and optional local network connections. It works locally and does not send files or hashes to a cloud service by default.\n"
        "\n"
        "Before you scan\n"
        "Choose what you want to inspect. Common Locations checks places where suspicious downloads often land, such as Downloads, Desktop, Documents, and temp folders. Add Files checks specific files. Add Folder checks everything inside a folder. Add Drive scans a whole drive. Add USB lists removable drives when Windows reports them.\n"
        "\n"
        "Premade rules\n"
        "Recommended is the best starting point for most people. Downloads focuses on scam installers, fake archives, and suspicious downloaded files. Scripts focuses on PowerShell, batch, JavaScript, VBScript, and token or credential access. Documents focuses on PDFs and Office macro-style behavior. Full enables all built-in packs and may show more items to review.\n"
        "\n"
        "Profiles\n"
        "Fast is the quickest scan. Deep checks more content and signatures. Forensic also checks startup, running processes, local network connections, and timeline output. Paranoid uses higher limits and may be slower or noisier.\n"
        "\n"
        "Scan coverage options\n"
        "Startup checks look for things that run automatically when Windows starts or when you sign in. Process checks inspect running process command lines and memory warning signs. Network-local telemetry maps active connections to processes without reputation lookups. Signature checks ask Windows whether executable files are signed by a trusted publisher. Include source-code files scans programming scripts outside the usual risky locations.\n"
        "\n"
        "Limits\n"
        "Max MB controls how much file content CLN reads for deeper checks. Bigger values can find more but take longer. Archive depth controls how far nested ZIP-style archives are opened. Recent days controls what counts as a new runnable file. Continuous polling repeats scans a few times to catch files that appear briefly.\n"
        "\n"
        "Rules and hashes\n"
        "Known bad hashes are exact SHA-256 file fingerprints you already trust as malicious. Known good hashes are exact file fingerprints you trust. Custom content rules, YARA rules, and YARA-lite rules are advanced options; most users can leave them empty and use Premade rules.\n"
        "\n"
        "Output and privacy\n"
        "Reports are saved locally. Redaction hides common secrets and your home path in output. Evidence bundles copy selected high-risk samples and metadata into a local case folder. JSON, CSV, and SARIF are mainly for command-line or tool integration use.\n"
        "\n"
        "Cleanup and restore\n"
        "Scanning does not delete anything by itself. Quarantine moves selected files into the quarantine folder and writes a manifest so they can be restored. Permanent delete is harder to undo and should only be used after you are sure. Restore manifest lets you put a quarantined file back if it was a false positive.\n"
        "\n"
        "Results\n"
        "A finding means CLN saw a warning sign, not always confirmed malware. High and critical findings deserve attention first. Read the detail, evidence, confidence, and recommended action before quarantining anything.\n"
        "\n"
        "CLI button\n"
        "Close and launch as CLI opens a PowerShell window with the same settings. Use it if you want terminal output, JSON or CSV, or easier copy-paste for support.\n"
        "\n"
        "Important safety note\n"
        "CLN is not a full antivirus replacement and cannot guarantee a machine is clean. For serious infections, use Windows Defender Offline, change passwords from a clean device, and consider professional incident response if sensitive accounts, money, business systems, or private data may be involved.\n"
    )


def apply_profile_defaults(args: argparse.Namespace) -> None:
    if args.profile == "fast":
        return
    if args.profile in {"deep", "forensic", "paranoid"}:
        args.signatures = True
        args.include_source = True
        args.archive_depth = max(args.archive_depth, 3)
        args.max_mb = max(args.max_mb, 150)
    if args.profile in {"forensic", "paranoid"}:
        args.startup = True
        args.processes = True
        args.network = True
        args.timeline = True
        args.max_mb = max(args.max_mb, 300)
    if args.profile == "paranoid":
        args.archive_depth = max(args.archive_depth, 5)
        args.recent_days = max(args.recent_days, 60)


def run_continuous_scan(scanner: Scanner, paths: list[Path], interval: int, count: int, *, verbose: bool) -> ScanSummary:
    combined: ScanSummary | None = None
    seen: set[tuple[str, str, str | None]] = set()
    for round_index in range(count):
        if verbose:
            say("Continuous", f"Polling round {round_index + 1}/{count}", "cyan")
        current = scanner.scan_paths(paths)
        if combined is None:
            combined = current
        else:
            combined.scanned_files += current.scanned_files
            combined.skipped_files += current.skipped_files
            combined.denied_files += current.denied_files
            combined.vanished_files += current.vanished_files
            combined.elapsed_seconds += current.elapsed_seconds
        for result in current.results:
            key = (result.path, result.sha256 or "", result.error)
            if key in seen:
                continue
            seen.add(key)
            if combined is not current:
                combined.results.append(result)
        if round_index < count - 1:
            time.sleep(interval)
    if combined is None:
        return ScanSummary(0, 0, [])
    combined.results.sort(key=lambda item: (-item.score, item.path.lower()))
    return combined


def load_builtin_rule_pack(name: str) -> list[ContentRule]:
    if name == "recommended":
        selected = ("downloads", "scripts", "documents")
    elif name == "full":
        selected = tuple(BUILTIN_RULE_PACK_RULES)
    else:
        selected = (name,)
    rules: list[ContentRule] = []
    for pack in selected:
        rules.extend(BUILTIN_RULE_PACK_RULES.get(pack, []))
    return rules


def available_scan_drives(*, removable_only: bool = False) -> list[Path]:
    if platform.system() != "Windows":
        roots = [Path("/") if Path("/").exists() else Path.cwd().anchor]
        return [Path(root) for root in roots if str(root)]
    try:
        import ctypes
    except ImportError:
        return []
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_RAMDISK = 6
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    drives: list[Path] = []
    for index in range(26):
        if not bitmask & (1 << index):
            continue
        root = f"{chr(65 + index)}:\\"
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        if removable_only and drive_type != DRIVE_REMOVABLE:
            continue
        if drive_type in {DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_REMOTE, DRIVE_RAMDISK}:
            drives.append(Path(root))
    return drives


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


def apply_yara_lite_rules(summary: ScanSummary, rules_path: Path) -> None:
    try:
        rules = load_yara_lite_rules(rules_path)
    except Exception as exc:  # noqa: BLE001
        summary.results.append(
            ScanResult(
                path=str(rules_path),
                kind="yara-lite",
                findings=[Finding("yara-lite-load-error", "YARA-lite rules could not be loaded", "medium", f"{type(exc).__name__}: {exc}")],
            )
        )
        return
    for result in summary.results:
        if result.kind != "file" or result.error:
            continue
        path = Path(result.path)
        try:
            size = path.stat().st_size
            data = path.read_bytes() if size <= MAX_TEXT_SCAN_BYTES else path.read_bytes()[:MAX_TEXT_SCAN_BYTES]
        except OSError as exc:
            result.findings.append(Finding("yara-lite-scan-error", "YARA-lite scan failed for file", "low", f"{type(exc).__name__}: {exc}"))
            continue
        for rule in rules:
            matched, detail = evaluate_yara_lite_rule(rule, data, size)
            if matched:
                result.findings.append(
                    Finding(
                        "yara-lite-match",
                        f"YARA-lite match: {rule['id']}",
                        str(rule.get("severity") or "high"),
                        detail,
                        remediation="Review the matching local rule and validate the file before taking action.",
                    )
                )


def load_yara_lite_rules(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        raise ValueError("YARA-lite file must contain a rules array")
    loaded: list[dict[str, object]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"rule #{index + 1} must be an object")
        rule_id = str(rule.get("id") or rule.get("name") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", rule_id):
            raise ValueError(f"rule #{index + 1} has an invalid id")
        strings = rule.get("strings") or {}
        if not isinstance(strings, dict):
            raise ValueError(f"rule {rule_id} strings must be an object")
        parsed_strings: dict[str, tuple[str, bytes]] = {}
        for name, value in strings.items():
            token = str(name).lstrip("$")
            if not re.fullmatch(r"[A-Za-z0-9_]{1,40}", token):
                raise ValueError(f"rule {rule_id} has invalid string id {name}")
            if isinstance(value, dict):
                kind = str(value.get("type") or "text")
                raw = str(value.get("value") or "")
            else:
                raw = str(value)
                kind = "hex" if re.fullmatch(r"(?:[0-9A-Fa-f?]{2}\s*)+", raw) else "text"
            if kind == "hex":
                parsed = parse_yara_lite_hex(raw)
            elif kind == "regex":
                parsed = raw.encode("utf-8")
            else:
                parsed = raw.encode("utf-8")
            parsed_strings[token] = (kind, parsed)
        condition = str(rule.get("condition") or " or ".join(f"${name}" for name in parsed_strings))
        severity = str(rule.get("severity") or "high").lower()
        if severity not in SEVERITY_SCORE:
            raise ValueError(f"rule {rule_id} has invalid severity {severity}")
        loaded.append({"id": rule_id, "strings": parsed_strings, "condition": condition, "severity": severity})
    return loaded


def parse_yara_lite_hex(value: str) -> bytes:
    normalized = re.sub(r"\s+", "", value)
    if "?" in normalized:
        normalized = normalized.replace("?", "0")
    if len(normalized) % 2:
        raise ValueError("hex pattern has an odd number of nibbles")
    return bytes.fromhex(normalized)


def evaluate_yara_lite_rule(rule: dict[str, object], data: bytes, file_size: int) -> tuple[bool, str]:
    strings = rule.get("strings")
    if not isinstance(strings, dict):
        return False, ""
    matches: dict[str, bool] = {}
    details: list[str] = []
    for name, item in strings.items():
        if isinstance(item, tuple) and len(item) == 2:
            kind, pattern = item
        elif isinstance(item, dict):
            kind = str(item.get("type") or "text")
            raw_value = str(item.get("value") or "")
            pattern = parse_yara_lite_hex(raw_value) if kind == "hex" else raw_value.encode("utf-8")
        else:
            raw_value = str(item)
            kind = "hex" if re.fullmatch(r"(?:[0-9A-Fa-f?]{2}\s*)+", raw_value) else "text"
            pattern = parse_yara_lite_hex(raw_value) if kind == "hex" else raw_value.encode("utf-8")
        matched = False
        if kind == "regex":
            try:
                matched = re.search(pattern.decode("utf-8", errors="replace").encode("utf-8"), data, flags=re.IGNORECASE | re.DOTALL) is not None
            except re.error:
                matched = False
        elif kind == "text":
            matched = bytes(pattern).lower() in data.lower()
        else:
            matched = bytes(pattern) in data
        matches[str(name)] = matched
        if matched:
            details.append(f"${name}")
    condition = str(rule.get("condition") or "")
    expression = condition
    expression = re.sub(r"\bfilesize\s*([<>]=?|==)\s*(\d+)\s*(KB|MB|B)?", lambda m: str(compare_filesize(file_size, m.group(1), int(m.group(2)), m.group(3) or "B")), expression, flags=re.IGNORECASE)
    expression = re.sub(r"\bentropy\s*([<>]=?|==)\s*(\d+(?:\.\d+)?)", lambda m: str(compare_number(estimate_entropy_bytes(data), m.group(1), float(m.group(2)))), expression, flags=re.IGNORECASE)
    for name, matched in sorted(matches.items(), key=lambda item: len(item[0]), reverse=True):
        expression = re.sub(rf"\${re.escape(name)}\b", str(matched), expression)
    if not re.fullmatch(r"[\sTrueFalsandorot()]+", expression):
        return False, "unsupported condition"
    try:
        matched = bool(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307 - expression is restricted above.
    except Exception:
        matched = False
    return matched, f"condition={condition}; matched={', '.join(details) or 'condition only'}"


def compare_filesize(actual: int, op: str, expected: int, unit: str) -> bool:
    multiplier = {"B": 1, "KB": 1024, "MB": 1024 * 1024}[unit.upper()]
    return compare_number(float(actual), op, float(expected * multiplier))


def compare_number(actual: float, op: str, expected: float) -> bool:
    if op == ">":
        return actual > expected
    if op == ">=":
        return actual >= expected
    if op == "<":
        return actual < expected
    if op == "<=":
        return actual <= expected
    return actual == expected


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

    timeline = build_timeline(summary)
    if timeline:
        lines.extend(["", "Timeline"])
        for event in timeline[:500]:
            lines.append(
                f"  {output_text(event['time'], redact=redact)} | {output_text(event['kind'], redact=redact)} | "
                f"{output_text(event['severity'], redact=redact)} | {output_text(event['path'], redact=redact)} | "
                f"{output_text(event['summary'], redact=redact)}"
            )

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


def build_timeline(summary: ScanSummary) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for result in summary.results:
        when = result.modified or ""
        if not when and result.kind in {"registry", "startup", "scheduled-task", "process", "network", "wmi-persistence", "browser-extension"}:
            when = datetime.now().isoformat(timespec="seconds")
        if not when:
            continue
        top = max((finding.severity for finding in result.findings), key=lambda item: SEVERITY_SCORE.get(item, 0), default="info")
        summary_text = "; ".join(finding.rule_id for finding in result.findings[:3]) or result.error or result.verdict
        events.append(
            {
                "time": when,
                "kind": result.kind,
                "severity": top,
                "path": result.path,
                "summary": summary_text,
            }
        )
    return sorted(events, key=lambda item: (item["time"], item["path"].lower()))


def timeline_to_dict(timeline: list[dict[str, str]], *, redact: bool | str = True) -> list[dict[str, str]]:
    return [
        {
            "time": output_text(event["time"], redact=redact),
            "kind": output_text(event["kind"], redact=redact),
            "severity": output_text(event["severity"], redact=redact),
            "path": output_text(event["path"], redact=redact),
            "summary": output_text(event["summary"], redact=redact),
        }
        for event in timeline
    ]


def export_evidence_bundle(bundle_root: Path, summary: ScanSummary, paths: list[Path], cleanup_report: list[str], *, redact: bool | str = True) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    case_dir = bundle_root / f"cln-case-{timestamp}"
    samples_dir = case_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=False)
    secure_write_text_file(case_dir / "summary.json", json.dumps(summary.to_dict(redact=redact), indent=2))
    secure_write_text_file(case_dir / "timeline.json", json.dumps(timeline_to_dict(build_timeline(summary), redact=redact), indent=2))
    secure_write_text_file(case_dir / "cleanup.log", "\n".join(output_text(line, redact=redact) for line in cleanup_report))
    secure_write_text_file(case_dir / "targets.txt", "\n".join(output_text(path, redact=redact) for path in paths))
    copied: list[dict[str, object]] = []
    for result in summary.results:
        if result.kind != "file" or not result.findings or not result.sha256:
            continue
        if not any(finding.severity in {"critical", "high"} for finding in result.findings):
            continue
        source = Path(result.path)
        try:
            if not source.is_file() or source.stat().st_size > 50 * 1024 * 1024:
                continue
            sample_name = f"{result.sha256[:12]}_{re.sub(r'[^A-Za-z0-9._-]+', '_', source.name)}.sample"
            destination = samples_dir / sample_name
            shutil.copy2(source, destination)
            copied.append({"source": output_text(source, redact=redact), "sample": output_text(destination, redact=redact), "sha256": result.sha256, "size": result.size})
        except OSError as exc:
            copied.append({"source": output_text(source, redact=redact), "error": f"{type(exc).__name__}: {output_text(exc, redact=redact)}"})
    secure_write_text_file(case_dir / "samples-manifest.json", json.dumps(copied, indent=2))
    return case_dir


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
    return analyze_pe_bytes(sample, file_size=len(sample), file_mtime=None)


def analyze_pe_file(path: Path, sample: bytes, file_size: int, file_mtime: float | None) -> list[Finding]:
    data = sample
    if file_size <= MAX_STRUCTURED_TEXT_BYTES and file_size > len(sample):
        try:
            data = path.read_bytes()
        except OSError:
            data = sample
    return analyze_pe_bytes(data, file_size=file_size, file_mtime=file_mtime)


def analyze_pe_bytes(data: bytes, *, file_size: int, file_mtime: float | None) -> list[Finding]:
    info = parse_pe(data)
    if not info:
        return []
    findings: list[Finding] = []
    entry_section_name = ""
    now = int(time.time())
    if info.timestamp:
        timestamp_text = datetime.fromtimestamp(info.timestamp).isoformat(timespec="seconds")
        if info.timestamp > now + 86400:
            findings.append(Finding("pe-future-timestamp", "PE compile timestamp is in the future", "medium", timestamp_text))
        if file_mtime and info.timestamp < int(file_mtime) - (365 * 24 * 3600 * 5):
            findings.append(Finding("pe-stale-timestamp", "PE compile timestamp is much older than file modification time", "low", f"compiled={timestamp_text}, modified={datetime.fromtimestamp(file_mtime).isoformat(timespec='seconds')}"))

    for section in info.sections:
        lower_name = section.name.lower()
        if lower_name in SUSPICIOUS_PE_SECTION_NAMES or lower_name.startswith((".upx", ".vmp")):
            findings.append(Finding("pe-suspicious-section-name", "PE has a packer or protector section name", "high", section.name))
        if section.executable and section.writable:
            findings.append(Finding("pe-writable-code-section", "PE executable section is writable", "high", f"{section.name} characteristics=0x{section.characteristics:08x}"))
        if section.executable and section.raw_size and section.raw_pointer < len(data):
            section_bytes = data[section.raw_pointer : min(len(data), section.raw_pointer + min(section.raw_size, 262_144))]
            entropy = estimate_entropy_bytes(section_bytes)
            if entropy >= 7.35:
                findings.append(Finding("pe-high-entropy-executable-section", "PE executable section has high entropy", "high", f"{section.name} entropy={entropy:.2f}"))
        if info.entry_point_rva and section.virtual_address <= info.entry_point_rva < section.virtual_address + max(section.virtual_size, 1):
            entry_section_name = section.name
            if not section.executable:
                findings.append(Finding("pe-entrypoint-not-executable", "PE entry point is in a non-executable section", "medium", f"{section.name} rva=0x{info.entry_point_rva:x}"))

    if info.entry_point_rva and not entry_section_name:
        findings.append(Finding("pe-entrypoint-outside-sections", "PE entry point is outside declared sections", "high", f"rva=0x{info.entry_point_rva:x}"))
    elif entry_section_name and entry_section_name.lower() not in {".text", "code", ".code", "text"}:
        findings.append(Finding("pe-unusual-entrypoint-section", "PE entry point is in an unusual section", "low", entry_section_name))

    if info.imports:
        imphash = pe_imphash(info.imports)
        imported_names = {name.lower() for _, name in info.imports}
        risky = sorted(imported_names.intersection(HIGH_RISK_IMPORTS))
        if {"virtualallocex", "writeprocessmemory"}.issubset(imported_names) and ("createremotethread" in imported_names or "ntcreatethreadex" in imported_names):
            findings.append(Finding("pe-injection-imports", "PE imports common process injection APIs", "high", f"imphash={imphash}, imports={', '.join(risky[:12])}"))
        elif len(risky) >= 4:
            findings.append(Finding("pe-risky-import-cluster", "PE imports multiple risky Windows APIs", "medium", f"imphash={imphash}, imports={', '.join(risky[:12])}"))
    if info.export_table_rva and info.export_table_size:
        findings.append(Finding("pe-exports-present", "PE exposes exports", "low", f"rva=0x{info.export_table_rva:x}, size={info.export_table_size}"))
    if info.tls_table_rva and info.tls_table_size:
        findings.append(Finding("pe-tls-directory", "PE has a TLS directory that may contain callbacks", "medium", f"rva=0x{info.tls_table_rva:x}, size={info.tls_table_size}"))
    if info.resource_table_rva and info.resource_table_size:
        offset = rva_to_offset(info.resource_table_rva, info.sections)
        if offset is not None and offset < len(data):
            resource_bytes = data[offset : min(len(data), offset + min(info.resource_table_size, 262_144))]
            findings.append(Finding("pe-resource-hash", "PE resource table hash", "info", f"sha256={hashlib.sha256(resource_bytes).hexdigest()}, size={len(resource_bytes)}"))
    overlay_offset = pe_overlay_offset(info)
    if overlay_offset and file_size > overlay_offset:
        overlay_size = file_size - overlay_offset
        severity = "medium" if overlay_size >= 1024 * 1024 else "low"
        findings.append(Finding("pe-overlay-data", "PE has appended overlay data", severity, f"offset={overlay_offset}, size={format_bytes(overlay_size)}"))
    pdb_paths = sorted(set(match.decode("utf-8", errors="replace") for match in re.findall(rb"(?i)[A-Za-z]:\\[^<>\r\n]{3,180}\.pdb", data[:MAX_STRUCTURED_TEXT_BYTES])))
    for pdb_path in pdb_paths[:3]:
        findings.append(Finding("pe-pdb-path", "PE contains a PDB path", "low", pdb_path))
    version_strings = extract_pe_version_strings(data)
    if version_strings and version_metadata_mismatch(version_strings):
        findings.append(Finding("pe-version-metadata-mismatch", "PE version metadata has inconsistent company/product names", "low", "; ".join(f"{key}={value}" for key, value in version_strings.items())[:400]))
    return findings


def parse_pe(data: bytes) -> PEInfo | None:
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return None
    pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    if pe_offset > len(data) - 24 or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    file_header = pe_offset + 4
    machine, section_count, timestamp, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, file_header)
    optional_offset = file_header + 20
    section_offset = optional_offset + optional_size
    if section_count <= 0 or section_count > 96 or section_offset > len(data):
        return None
    if optional_offset + 2 > len(data):
        return None
    magic = int.from_bytes(data[optional_offset : optional_offset + 2], "little", signed=False)
    if magic not in {0x10B, 0x20B}:
        return None
    info = PEInfo(machine=machine, timestamp=timestamp, is_pe64=magic == 0x20B)
    if optional_offset + 20 <= len(data):
        info.entry_point_rva = int.from_bytes(data[optional_offset + 16 : optional_offset + 20], "little", signed=False)
    data_directory_offset = optional_offset + (96 if magic == 0x10B else 112)
    if data_directory_offset + 8 <= len(data):
        info.export_table_rva = int.from_bytes(data[data_directory_offset : data_directory_offset + 4], "little", signed=False)
        info.export_table_size = int.from_bytes(data[data_directory_offset + 4 : data_directory_offset + 8], "little", signed=False)
        info.import_table_rva = int.from_bytes(data[data_directory_offset + 8 : data_directory_offset + 12], "little", signed=False)
        info.import_table_size = int.from_bytes(data[data_directory_offset + 12 : data_directory_offset + 16], "little", signed=False)
    if data_directory_offset + 24 <= len(data):
        info.resource_table_rva = int.from_bytes(data[data_directory_offset + 16 : data_directory_offset + 20], "little", signed=False)
        info.resource_table_size = int.from_bytes(data[data_directory_offset + 20 : data_directory_offset + 24], "little", signed=False)
    if data_directory_offset + 56 <= len(data):
        info.tls_table_rva = int.from_bytes(data[data_directory_offset + 72 : data_directory_offset + 76], "little", signed=False) if data_directory_offset + 80 <= len(data) else 0
        info.tls_table_size = int.from_bytes(data[data_directory_offset + 76 : data_directory_offset + 80], "little", signed=False) if data_directory_offset + 80 <= len(data) else 0
    if data_directory_offset + 56 <= len(data):
        info.debug_table_rva = int.from_bytes(data[data_directory_offset + 48 : data_directory_offset + 52], "little", signed=False)
        info.debug_table_size = int.from_bytes(data[data_directory_offset + 52 : data_directory_offset + 56], "little", signed=False)
    for index in range(section_count):
        offset = section_offset + (index * 40)
        if offset + 40 > len(data):
            break
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section-{index}"
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, offset + 8)
        characteristics = int.from_bytes(data[offset + 36 : offset + 40], "little", signed=False)
        info.sections.append(PESection(name, virtual_size, virtual_address, raw_size, raw_pointer, characteristics))
    info.imports = parse_pe_imports(data, info)
    return info


def pe_overlay_offset(info: PEInfo) -> int:
    offsets = [section.raw_pointer + section.raw_size for section in info.sections if section.raw_pointer and section.raw_size]
    return max(offsets) if offsets else 0


def extract_pe_version_strings(data: bytes) -> dict[str, str]:
    text = data[:MAX_STRUCTURED_TEXT_BYTES].decode("utf-16-le", errors="ignore") + "\n" + data[:MAX_STRUCTURED_TEXT_BYTES].decode("latin-1", errors="ignore")
    wanted = ("CompanyName", "FileDescription", "OriginalFilename", "ProductName", "InternalName")
    values: dict[str, str] = {}
    for key in wanted:
        match = re.search(rf"(?is){re.escape(key)}\x00?\s*([\w .,\-(){{}}]{{2,120}})", text)
        if match:
            values[key] = re.sub(r"\s+", " ", match.group(1)).strip(" \0")
    return values


def version_metadata_mismatch(values: dict[str, str]) -> bool:
    company = values.get("CompanyName", "").lower()
    product = values.get("ProductName", "").lower()
    original = values.get("OriginalFilename", "").lower()
    if not values:
        return False
    microsoft_names = ("microsoft", "windows", "defender", "office")
    claims_microsoft = any(token in company or token in product for token in microsoft_names)
    odd_original = bool(original and not original.endswith((".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl")))
    generic_company = company in {"", "todo", "unknown", "company", "your company"}
    return (claims_microsoft and original and not any(token in original for token in ("microsoft", "windows", "office", "defender", "ms"))) or odd_original or generic_company


def rva_to_offset(rva: int, sections: list[PESection]) -> int | None:
    for section in sections:
        span = max(section.virtual_size, section.raw_size, 1)
        if section.virtual_address <= rva < section.virtual_address + span:
            return section.raw_pointer + (rva - section.virtual_address)
    return None


def read_c_string(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end == -1:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", errors="ignore").strip()


def parse_pe_imports(data: bytes, info: PEInfo) -> list[tuple[str, str]]:
    if not info.import_table_rva:
        return []
    descriptor_offset = rva_to_offset(info.import_table_rva, info.sections)
    if descriptor_offset is None:
        return []
    imports: list[tuple[str, str]] = []
    thunk_size = 8 if info.is_pe64 else 4
    for descriptor_index in range(256):
        offset = descriptor_offset + (descriptor_index * 20)
        if offset + 20 > len(data):
            break
        original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, offset)
        if not any((original_first_thunk, name_rva, first_thunk)):
            break
        dll_offset = rva_to_offset(name_rva, info.sections)
        dll_name = read_c_string(data, dll_offset) if dll_offset is not None else ""
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva, info.sections)
        if thunk_offset is None:
            continue
        for thunk_index in range(4096):
            entry_offset = thunk_offset + (thunk_index * thunk_size)
            if entry_offset + thunk_size > len(data):
                break
            thunk_value = int.from_bytes(data[entry_offset : entry_offset + thunk_size], "little", signed=False)
            if thunk_value == 0:
                break
            ordinal_mask = 0x8000000000000000 if thunk_size == 8 else 0x80000000
            if thunk_value & ordinal_mask:
                api_name = f"ord{thunk_value & 0xFFFF}"
            else:
                hint_name_offset = rva_to_offset(thunk_value, info.sections)
                api_name = read_c_string(data, hint_name_offset + 2) if hint_name_offset is not None else ""
            if dll_name and api_name:
                imports.append((dll_name, api_name))
    return imports


def pe_imphash(imports: list[tuple[str, str]]) -> str:
    normalized = []
    for dll_name, api_name in imports:
        dll = dll_name.lower().rsplit(".", 1)[0]
        normalized.append(f"{dll}.{api_name.lower()}")
    return hashlib.md5(",".join(normalized).encode("utf-8")).hexdigest()


def sorted_review_results(results: list[ScanResult]) -> list[ScanResult]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def key(result: ScanResult) -> tuple[int, int, str]:
        severities = [finding.severity for finding in result.findings] or ["info"]
        best = min(severity_rank.get(severity, 5) for severity in severities)
        priority = 0 if any(severity in {"critical", "high"} for severity in severities) else 1
        return (priority, best, result.path.lower())

    return sorted(results, key=key)


def result_summary(result: ScanResult) -> str:
    top_severity = max((SEVERITY_SCORE.get(finding.severity, 0) for finding in result.findings), default=0)
    severity = next((name for name, score in SEVERITY_SCORE.items() if score == top_severity), "info")
    titles = "; ".join(finding.title for finding in result.findings[:3])
    if len(result.findings) > 3:
        titles += f"; +{len(result.findings) - 3} more"
    return f"{severity.upper()} | {result.verdict.upper()} | {result.path} | {titles or result.error or 'No findings'}"


def launch_removal_gui(summary: ScanSummary, paths: list[Path], quarantine_dir: Path, cleanable_hashes: set[str], *, redact: bool | str = True) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except Exception as exc:  # noqa: BLE001
        print(f"Could not open GUI: {type(exc).__name__}: {exc}")
        print_report(summary, paths, signatures_enabled=False, redact=redact)
        return

    root = tk.Tk()
    root.title("CLN Removal Tool")
    root.geometry("1100x720")

    recommendation = "We recommend you to remove high & critical first, make sure the scan is correct and not a false flag."
    tk.Label(root, text=recommendation, anchor="w", fg="#7a2e00", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=10, pady=(10, 4))

    top = ttk.Frame(root)
    top.pack(fill="both", expand=True, padx=10, pady=6)
    filter_bar = ttk.Frame(root)
    filter_bar.pack(fill="x", padx=10, pady=(0, 6))
    severity_filter = tk.StringVar(value="all")
    search_filter = tk.StringVar(value="")
    hide_low = tk.BooleanVar(value=False)
    ttk.Label(filter_bar, text="Severity").pack(side="left")
    severity_box = ttk.Combobox(filter_bar, textvariable=severity_filter, values=("all", "critical", "high", "medium", "low", "info"), width=10, state="readonly")
    severity_box.pack(side="left", padx=(4, 10))
    ttk.Checkbutton(filter_bar, text="Hide low/info", variable=hide_low).pack(side="left", padx=(0, 10))
    ttk.Label(filter_bar, text="Search").pack(side="left")
    search_entry = ttk.Entry(filter_bar, textvariable=search_filter, width=36)
    search_entry.pack(side="left", padx=(4, 10))
    columns = ("severity", "verdict", "kind", "path", "info")
    tree = ttk.Treeview(top, columns=columns, show="headings", selectmode="extended", height=18)
    for column, width in (("severity", 90), ("verdict", 90), ("kind", 110), ("path", 390), ("info", 380)):
        tree.heading(column, text=column.title())
        tree.column(column, width=width, stretch=column in {"path", "info"})
    scrollbar = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    details = tk.Text(root, height=12, wrap="word")
    details.pack(fill="both", expand=False, padx=10, pady=(0, 8))
    details.configure(state="disabled")

    status_var = tk.StringVar(value=f"Scanned {summary.scanned_files} file(s). Select findings to quarantine or delete.")
    status = ttk.Label(root, textvariable=status_var, anchor="w")
    status.pack(fill="x", padx=10, pady=(0, 8))

    hits = sorted_review_results([result for result in summary.results if result.findings or result.error])
    iid_to_result: dict[str, ScanResult] = {}

    def result_display_severity(result: ScanResult) -> str:
        severities = [finding.severity for finding in result.findings]
        return "critical" if "critical" in severities else "high" if "high" in severities else "medium" if "medium" in severities else "low" if "low" in severities else "info"

    def refresh_tree(*_: object) -> None:
        tree.delete(*tree.get_children())
        iid_to_result.clear()
        wanted = severity_filter.get()
        query = search_filter.get().lower().strip()
        for index, result in enumerate(hits):
            display_severity = result_display_severity(result)
            if wanted != "all" and display_severity != wanted:
                continue
            if hide_low.get() and display_severity in {"low", "info"}:
                continue
            info = "; ".join(f"{finding.rule_id}: {finding.title}" for finding in result.findings[:2]) or result.error or ""
            haystack = f"{result.path} {result.kind} {result.verdict} {info}".lower()
            if query and query not in haystack:
                continue
            iid = str(index)
            iid_to_result[iid] = result
            tree.insert("", "end", iid=iid, values=(display_severity.upper(), result.verdict.upper(), result.kind, output_text(result.path, redact=redact), output_text(info, redact=redact, limit=260)))
        status_var.set(f"Showing {len(tree.get_children())} finding(s). Select findings to quarantine, export, or restore.")

    def selected_results() -> list[ScanResult]:
        return [iid_to_result[item] for item in tree.selection() if item in iid_to_result]

    def show_details(_: object | None = None) -> None:
        selected = selected_results()
        details.configure(state="normal")
        details.delete("1.0", "end")
        if not selected:
            details.insert("end", "Select a finding to view details.\n")
        for result in selected[:8]:
            details.insert("end", f"{result.path}\n")
            details.insert("end", f"Kind: {result.kind}  Verdict: {result.verdict}  Score: {result.score}\n")
            if result.size is not None:
                details.insert("end", f"Size: {result.size} bytes\n")
            if result.modified:
                details.insert("end", f"Modified: {result.modified}\n")
            if result.file_type:
                details.insert("end", f"Type: {result.file_type}\n")
            if result.sha256:
                details.insert("end", f"SHA-256: {result.sha256}\n")
            if result.error:
                details.insert("end", f"Error: {result.error}\n")
            for finding in result.findings:
                details.insert("end", f"- {finding.severity.upper()} {finding.rule_id}: {finding.title}\n")
                details.insert("end", f"  Detail: {finding.detail}\n")
                if finding.evidence:
                    details.insert("end", f"  Evidence: {finding.evidence}\n")
                if finding.remediation:
                    details.insert("end", f"  Info: {finding.remediation}\n")
            details.insert("end", "\n")
        details.configure(state="disabled")

    def remove_selected(*, delete: bool) -> None:
        selected = selected_results()
        if not selected:
            messagebox.showinfo("CLN Removal Tool", "Select one or more file findings first.")
            return
        action = "permanently delete" if delete else "quarantine"
        if not messagebox.askyesno("Confirm removal", f"CLN will {action} selected file results only. Continue?\n\n{recommendation}"):
            return
        report = remove_scan_results(selected, quarantine_dir, delete=delete)
        status_var.set("; ".join(report[:3]) + (f"; +{len(report) - 3} more" if len(report) > 3 else ""))
        messagebox.showinfo("Removal results", "\n".join(report[:40]))

    def full_known_bad_cleanup() -> None:
        if not messagebox.askyesno("Full known-bad cleanup", "Run full cleanup for the built-in known-bad SHA-256 profile?\n\nFiles are hash-verified before removal and quarantined by default."):
            return
        report = clean_known_bad(summary, quarantine_dir, delete=False, cleanable_hashes=cleanable_hashes)
        status_var.set("; ".join(report[:3]) + (f"; +{len(report) - 3} more" if len(report) > 3 else ""))
        messagebox.showinfo("Known-bad cleanup results", "\n".join(report[:60]))

    def select_high_critical() -> None:
        selected = []
        for iid in tree.get_children():
            result = iid_to_result.get(str(iid))
            if result and result_display_severity(result) in {"critical", "high"}:
                selected.append(iid)
        tree.selection_set(selected)
        show_details()

    def export_selected() -> None:
        selected = selected_results()
        if not selected:
            messagebox.showinfo("CLN Removal Tool", "Select one or more findings first.")
            return
        export_summary = ScanSummary(scanned_files=len(selected), skipped_files=0, results=selected)
        try:
            path = export_evidence_bundle(Path("reports") / "gui-bundles", export_summary, paths, [], redact=redact)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Export failed", f"{type(exc).__name__}: {exc}")
            return
        status_var.set(f"Exported selected evidence: {path}")

    def restore_from_manifest() -> None:
        from tkinter import filedialog

        manifest = filedialog.askopenfilename(title="Select CLN quarantine manifest", filetypes=(("CLN manifests", "*.manifest.json"), ("JSON", "*.json"), ("All files", "*.*")))
        if not manifest:
            return
        report = restore_quarantine_manifest(Path(manifest))
        status_var.set("; ".join(report[:3]))
        messagebox.showinfo("Restore results", "\n".join(report[:20]))

    tree.bind("<<TreeviewSelect>>", show_details)
    severity_box.bind("<<ComboboxSelected>>", refresh_tree)
    search_filter.trace_add("write", refresh_tree)
    hide_low.trace_add("write", refresh_tree)
    buttons = ttk.Frame(root)
    buttons.pack(fill="x", padx=10, pady=(0, 10))
    ttk.Button(buttons, text="Select High/Critical", command=select_high_critical).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Export Selected", command=export_selected).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Quarantine Selected", command=lambda: remove_selected(delete=False)).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Delete Selected", command=lambda: remove_selected(delete=True)).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Restore Quarantine", command=restore_from_manifest).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Full Known-Bad Cleanup", command=full_known_bad_cleanup).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text="Close", command=root.destroy).pack(side="right")
    refresh_tree()
    show_details()
    root.mainloop()


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
        if normalized not in yielded:
            yielded.add(normalized)
            yield encoding, normalized
        resolved = resolve_script_strings(text)
        if resolved:
            resolved_bytes = resolved.encode("utf-8", errors="replace")
            if resolved_bytes not in yielded:
                yielded.add(resolved_bytes)
                yield f"{encoding} string-resolution", resolved_bytes


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


def resolve_script_strings(text: str) -> str:
    if len(text) > MAX_STRUCTURED_TEXT_BYTES:
        text = text[:MAX_STRUCTURED_TEXT_BYTES]
    parts = [text]
    strings = extract_quoted_strings(text)
    if strings:
        parts.append("\n".join(strings))
    for match in re.finditer(r"(?is)(?:['\"][^'\"]{1,200}['\"]\s*(?:\+|&)\s*){1,20}['\"][^'\"]{1,200}['\"]", text):
        values = re.findall(r"['\"]([^'\"]{1,200})['\"]", match.group(0))
        if len(values) >= 2:
            joined = "".join(values)
            if joined:
                parts.append(joined)
    variables = resolve_simple_variables(text)
    if variables:
        parts.append("\n".join(f"{name}={value}" for name, value in variables.items()))
        expanded = text
        for name, value in variables.items():
            expanded = re.sub(rf"\${re.escape(name)}\b", value, expanded)
        if expanded != text:
            parts.append(expanded)
    for match in re.finditer(r"(?is)(['\"])(.*?)\1\s*-[fF]\s*([^\r\n;]{1,500})", text):
        template = match.group(2)
        values = re.findall(r"['\"]([^'\"]{0,120})['\"]", match.group(3))
        if values:
            rendered = template
            for index, value in enumerate(values):
                rendered = rendered.replace("{" + str(index) + "}", value)
            parts.append(rendered)
    for match in re.finditer(r"(?is)(['\"])([^'\"]{2,500})\1\s*\.\s*(?:split\(\s*['\"]{2}\s*\)\s*)?reverse\(\s*\)\s*\.\s*join\(\s*['\"]{2}\s*\)", text):
        parts.append(match.group(2)[::-1])
    for match in re.finditer(r"(?is)(['\"])([^'\"]{1,500})\1\s*\.\s*replace\(\s*(['\"])(.*?)\3\s*,\s*(['\"])(.*?)\5\s*\)", text):
        parts.append(match.group(2).replace(match.group(4), match.group(6)))
    for match in re.finditer(r"(?is)\[string\]\s*::\s*join\(\s*['\"]{2}\s*,\s*\((.*?)\)\s*\)", text):
        values = re.findall(r"['\"]([^'\"]{1,100})['\"]", match.group(1))
        if values:
            parts.append("".join(values))
    for match in re.finditer(r"(?is)(?:-join\s*)?\(?\s*([0-9]{2,3}(?:\s*,\s*[0-9]{2,3}){2,200})\s*\)?\s*\|\s*%?\s*\{\s*\[char\]\s*\$_\s*\}", text):
        chars = []
        for item in re.findall(r"[0-9]{2,3}", match.group(1)):
            value = int(item)
            if 0 <= value <= 255:
                chars.append(chr(value))
        if chars:
            parts.append("".join(chars))
    for match in re.finditer(r"(?is)\[Text\.Encoding\]::UTF8\.GetString\(\s*\[Convert\]::FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{12,})['\"]\s*\)\s*\)", text):
        decoded = decode_base64_text(match.group(1))
        if decoded:
            parts.append(decoded)
    for match in re.finditer(r"(?is)([0-9]{1,3}(?:\s*,\s*[0-9]{1,3}){3,200})\s*(?:\||\))?.{0,80}?(?:-bxor|\^)\s*([0-9]{1,3})", text):
        key = int(match.group(2))
        chars = []
        for item in re.findall(r"[0-9]{1,3}", match.group(1)):
            value = int(item) ^ key
            if 0 <= value <= 255:
                chars.append(chr(value))
        decoded = "".join(chars)
        if is_probably_text(decoded):
            parts.append(decoded)
    normalized = "\n".join(dict.fromkeys(part for part in parts if part))
    normalized = normalized.replace("`", "")
    return normalized if normalized != text else ""


def resolve_simple_variables(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in re.finditer(r"(?im)^\s*\$([A-Za-z_][\w-]{0,40})\s*=\s*(.+?)\s*$", text):
        name = match.group(1)
        expression = match.group(2)
        pieces = re.findall(r"['\"]([^'\"]{0,200})['\"]", expression)
        if pieces and re.fullmatch(r"(?is)\s*['\"][^'\"]*['\"](?:\s*(?:\+|&)\s*['\"][^'\"]*['\"])*\s*", expression):
            values[name] = "".join(pieces)
    return values


def decode_base64_text(value: str) -> str:
    padded = value + ("=" * (-len(value) % 4))
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return ""
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            text = raw.decode(encoding)
        except UnicodeError:
            continue
        if is_probably_text(text):
            return text
    return ""


def extract_quoted_strings(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"(?s)(['\"])(.{1,500}?)\1", text):
        value = match.group(2)
        if any(char.isalnum() for char in value):
            values.append(value)
    return values[:500]


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


def read_structured_document_bytes(path: Path, sample: bytes, limit: int = MAX_PDF_OBJECT_SCAN_BYTES) -> bytes:
    try:
        size = path.stat().st_size
        if size <= limit and size > len(sample):
            return path.read_bytes()
    except OSError:
        pass
    return sample


def parse_lnk_command(data: bytes) -> tuple[str, str]:
    parsed = parse_lnk_metadata(data)
    return parsed.get("target", ""), parsed.get("arguments", "")


def parse_lnk_metadata(data: bytes) -> dict[str, str]:
    if len(data) < 0x4C or not data.startswith(b"\x4C\x00\x00\x00\x01\x14\x02\x00"):
        return {}
    offset = 0x4C
    flags = int.from_bytes(data[0x14:0x18], "little", signed=False)
    is_unicode = bool(flags & 0x80)
    metadata = {
        "flags": f"0x{flags:08x}",
        "hotkey": f"0x{int.from_bytes(data[0x40:0x42], 'little', signed=False):04x}" if len(data) >= 0x42 else "",
        "show_command": str(int.from_bytes(data[0x3C:0x40], "little", signed=False)) if len(data) >= 0x40 else "",
    }
    if flags & 0x01:
        if offset + 2 > len(data):
            return metadata
        id_list_size = int.from_bytes(data[offset : offset + 2], "little", signed=False)
        offset += 2 + id_list_size
    if flags & 0x02:
        if offset + 4 > len(data):
            return metadata
        link_info_size = int.from_bytes(data[offset : offset + 4], "little", signed=False)
        metadata.update(parse_lnk_link_info(data[offset : min(len(data), offset + link_info_size)]))
        offset += link_info_size
    names = {0x04: "name", 0x08: "relative_path", 0x10: "working_dir", 0x20: "arguments", 0x40: "icon_path"}
    values: dict[str, str] = {}
    for bit, name in names.items():
        if not (flags & bit):
            continue
        if offset + 2 > len(data):
            break
        char_count = int.from_bytes(data[offset : offset + 2], "little", signed=False)
        offset += 2
        byte_count = char_count * 2 if is_unicode else char_count
        if offset + byte_count > len(data):
            break
        raw = data[offset : offset + byte_count]
        offset += byte_count
        value = raw.decode("utf-16-le" if is_unicode else "cp1252", errors="replace").strip("\0\r\n ")
        values[name] = value
    metadata.update(values)
    metadata["target"] = metadata.get("local_base_path") or values.get("relative_path") or values.get("name") or ""
    return metadata


def parse_lnk_link_info(data: bytes) -> dict[str, str]:
    if len(data) < 28:
        return {}
    flags = int.from_bytes(data[8:12], "little", signed=False)
    local_base_offset = int.from_bytes(data[16:20], "little", signed=False)
    common_path_suffix_offset = int.from_bytes(data[24:28], "little", signed=False)
    values: dict[str, str] = {}
    if flags & 0x01 and 0 < local_base_offset < len(data):
        values["local_base_path"] = read_lnk_c_string(data, local_base_offset)
    if 0 < common_path_suffix_offset < len(data):
        values["common_path_suffix"] = read_lnk_c_string(data, common_path_suffix_offset)
    return values


def read_lnk_c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("cp1252", errors="replace").strip()


def scan_lnk_content(path: Path, data: bytes) -> list[Finding]:
    metadata = parse_lnk_metadata(data)
    target = metadata.get("target", "")
    arguments = metadata.get("arguments", "")
    command = " ".join(part for part in (target, arguments) if part).strip()
    if not command:
        return []
    findings: list[Finding] = []
    command_bytes = command.encode("utf-8", errors="replace")
    if re.search(r"(?is)\b(?:powershell|pwsh|mshta|wscript|cscript|rundll32|cmd|regsvr32)(?:\.exe)?\b", command):
        findings.append(
            Finding(
                "shortcut-suspicious-target",
                "Shortcut launches a suspicious command interpreter",
                "high",
                f"{path.name}: {command[:300]}; working_dir={metadata.get('working_dir', '')}; icon={metadata.get('icon_path', '')}; hotkey={metadata.get('hotkey', '')}; show={metadata.get('show_command', '')}",
                safe_excerpt(command_bytes),
                "Inspect the parsed shortcut target and arguments before opening it.",
            )
        )
    if arguments and not any(finding.rule_id == "shortcut-suspicious-target" for finding in findings):
        findings.append(Finding("shortcut-has-arguments", "Shortcut has explicit command-line arguments", "low", f"{path.name}: {command[:300]}"))
    if metadata.get("icon_path") and any(token in metadata["icon_path"].lower() for token in ("shell32.dll", "imageres.dll")) and re.search(r"(?is)\b(?:powershell|cmd|mshta|wscript|rundll32)", command):
        findings.append(Finding("shortcut-deceptive-icon", "Shortcut uses a generic system icon while launching a risky command", "medium", metadata["icon_path"]))
    for finding in scan_content_rule_matches(command_bytes, "Pattern matched in parsed shortcut command line"):
        findings.append(Finding(f"shortcut-{finding.rule_id}", f"Shortcut command: {finding.title}", finding.severity, finding.detail, finding.evidence, finding.remediation))
    return findings


def extract_pdf_analysis_bytes(data: bytes) -> bytes:
    chunks = [data[:MAX_TEXT_SCAN_BYTES]]
    for match in re.finditer(rb"(?is)(\d+)\s+(\d+)\s+obj(.*?)endobj", data[:MAX_PDF_OBJECT_SCAN_BYTES]):
        object_id = match.group(1) + b" " + match.group(2) + b" obj"
        body = match.group(3)
        chunks.append(b"\n%% object " + object_id + b" offset " + str(match.start()).encode("ascii") + b"\n")
        chunks.append(body[:200_000])
        stream_match = re.search(rb"(?is)<<(.*?)>>\s*stream\r?\n(.*?)\r?\nendstream", body)
        if stream_match:
            stream_dict = stream_match.group(1)
            stream_data = stream_match.group(2)
            decoded = decode_pdf_stream(stream_dict, stream_data)
            chunks.append(decoded[:200_000])
    return b"\n".join(chunks)


def decode_pdf_stream(stream_dict: bytes, stream_data: bytes) -> bytes:
    data = stream_data.strip(b"\r\n")
    filters = re.findall(rb"/(?:Filter\s*)?/(FlateDecode|ASCIIHexDecode|ASCII85Decode|AHx|A85|Fl)", stream_dict)
    if not filters:
        return data
    for raw_filter in filters:
        name = raw_filter.lower()
        try:
            if name in {b"flatedecode", b"fl"}:
                data = zlib.decompress(data)
            elif name in {b"asciihexdecode", b"ahx"}:
                data = asciihex_decode(data)
            elif name in {b"ascii85decode", b"a85"}:
                data = base64.a85decode(data.replace(b"<~", b"").replace(b"~>", b""), adobe=False)
        except (ValueError, zlib.error, binascii.Error):
            break
    return data


def asciihex_decode(data: bytes) -> bytes:
    hex_text = re.sub(rb"\s+", b"", data.split(b">", 1)[0])
    if len(hex_text) % 2:
        hex_text += b"0"
    return bytes.fromhex(hex_text.decode("ascii", errors="ignore"))


def scan_pdf_content(path: Path, data: bytes) -> list[Finding]:
    analysis = extract_pdf_analysis_bytes(data)
    findings: list[Finding] = []
    rules = (
        ("pdf-javascript", "PDF contains JavaScript action", rb"(?is)/(?:JavaScript|JS)\b"),
        ("pdf-open-action", "PDF contains an automatic open action", rb"(?is)/OpenAction\b"),
        ("pdf-launch-action", "PDF contains a launch action", rb"(?is)/Launch\b"),
        ("pdf-additional-action", "PDF contains additional automatic actions", rb"(?is)/AA\b"),
        ("pdf-uri-action", "PDF contains URI action", rb"(?is)/URI\b\s*(?:\(|<|/)"),
        ("pdf-embedded-file", "PDF contains embedded files", rb"(?is)/(?:EmbeddedFiles|Filespec|EmbeddedFile)\b"),
    )
    for rule_id, title, pattern in rules:
        match = re.search(pattern, analysis)
        if match:
            findings.append(
                Finding(
                    rule_id,
                    title,
                    "high" if rule_id in {"pdf-open-action", "pdf-launch-action", "pdf-embedded-file"} else "medium",
                    str(path.name),
                    describe_match(analysis, match.start(), match.end()),
                    "Open the PDF only in a sandboxed viewer and verify it with a dedicated PDF analysis tool.",
                )
            )
    return findings


def extract_ole_strings(data: bytes) -> bytes:
    chunks = [data[:MAX_TEXT_SCAN_BYTES]]
    for stream_name, stream_data in extract_ole_streams(data):
        chunks.append(f"\n%% ole stream {stream_name}\n".encode("utf-8", errors="replace"))
        chunks.append(stream_data[:200_000])
    for encoding in ("latin-1", "utf-16-le"):
        try:
            text = data[:MAX_STRUCTURED_TEXT_BYTES].decode(encoding, errors="ignore")
        except UnicodeError:
            continue
        strings = re.findall(r"[\x09\x0a\x0d\x20-\x7e]{5,}", text)
        if strings:
            chunks.append("\n".join(strings[:2000]).encode("utf-8", errors="replace"))
    return b"\n".join(chunks)


def extract_ole_streams(data: bytes) -> list[tuple[str, bytes]]:
    if not data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") or len(data) < 512:
        return []
    sector_shift = int.from_bytes(data[0x1E:0x20], "little", signed=False)
    if sector_shift not in {9, 12}:
        return []
    sector_size = 1 << sector_shift
    directory_start = int.from_bytes(data[0x30:0x34], "little", signed=False)
    fat_sector_count = int.from_bytes(data[0x2C:0x30], "little", signed=False)
    difat = [int.from_bytes(data[0x4C + index * 4 : 0x50 + index * 4], "little", signed=False) for index in range(109)]
    fat_sectors = [sector for sector in difat if sector < 0xFFFFFFF0][:fat_sector_count]
    fat: list[int] = []
    for sector in fat_sectors[:128]:
        raw = ole_sector(data, sector, sector_size)
        if not raw:
            continue
        fat.extend(int.from_bytes(raw[offset : offset + 4], "little", signed=False) for offset in range(0, len(raw), 4))
    directory_bytes = read_ole_chain(data, directory_start, fat, sector_size, limit=512 * 128)
    streams: list[tuple[str, bytes]] = []
    for offset in range(0, len(directory_bytes), 128):
        entry = directory_bytes[offset : offset + 128]
        if len(entry) < 128:
            break
        object_type = entry[66]
        if object_type != 2:
            continue
        name_len = int.from_bytes(entry[64:66], "little", signed=False)
        name_raw = entry[: max(0, name_len - 2)]
        name = name_raw.decode("utf-16-le", errors="replace").strip("\0")
        start_sector = int.from_bytes(entry[116:120], "little", signed=False)
        size = int.from_bytes(entry[120:124], "little", signed=False)
        if not name or size <= 0 or size > MAX_STRUCTURED_TEXT_BYTES or start_sector >= 0xFFFFFFF0:
            continue
        stream = read_ole_chain(data, start_sector, fat, sector_size, limit=min(size, MAX_STRUCTURED_TEXT_BYTES))
        streams.append((name, stream[:size]))
        if len(streams) >= 64:
            break
    return streams


def ole_sector(data: bytes, sector: int, sector_size: int) -> bytes:
    offset = 512 + sector * sector_size
    if offset < 0 or offset + sector_size > len(data):
        return b""
    return data[offset : offset + sector_size]


def read_ole_chain(data: bytes, start_sector: int, fat: list[int], sector_size: int, *, limit: int) -> bytes:
    chunks: list[bytes] = []
    sector = start_sector
    seen: set[int] = set()
    while sector < len(fat) and sector not in seen and len(b"".join(chunks)) < limit:
        seen.add(sector)
        chunk = ole_sector(data, sector, sector_size)
        if not chunk:
            break
        chunks.append(chunk)
        next_sector = fat[sector]
        if next_sector >= 0xFFFFFFF8:
            break
        sector = next_sector
    return b"".join(chunks)[:limit]


def scan_ole_content(path: Path, data: bytes) -> list[Finding]:
    analysis = extract_ole_strings(data)
    findings: list[Finding] = []
    for rule_id, title, pattern in (
        ("ole-vba-module", "OLE document contains VBA module stream indicators", rb"(?is)%% ole stream .*(?:VBA|dir|Module|ThisDocument|Sheet\d+)"),
        ("ole-vba-autostart", "OLE/VBA macro has auto-start trigger", rb"(?is)\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|AutoClose)\b"),
        ("ole-vba-shell", "OLE/VBA macro invokes shell or process execution", rb"(?is)\b(?:Shell|WScript\.Shell|CreateObject|WinExec|ShellExecute)\b.{0,200}\b(?:cmd|powershell|wscript|cscript|mshta|rundll32)?"),
        ("ole-vba-api-declare", "OLE/VBA macro declares suspicious Windows APIs", rb"(?is)\bDeclare\b.{0,160}\b(?:URLDownloadToFile|ShellExecute|WinExec|VirtualAlloc|WriteProcessMemory|CreateThread)\b"),
        ("ole-vba-obfuscation", "OLE/VBA macro has common obfuscation indicators", rb"(?is)\b(?:ChrW?|StrReverse|Environ|Execute|Eval)\b"),
    ):
        match = re.search(pattern, analysis)
        if match:
            findings.append(Finding(rule_id, title, "high" if "shell" in rule_id or "autostart" in rule_id else "medium", str(path.name), describe_match(analysis, match.start(), match.end()), "Open only with macros disabled and inspect the VBA project before trusting the document."))
    return findings


def scan_basic_document_content(path: Path, sample: bytes, file_type: str | None) -> list[Finding]:
    suffix = path.suffix.lower()
    findings: list[Finding] = []
    if file_type == "pdf-document" or suffix == ".pdf":
        findings.extend(scan_pdf_content(path, read_structured_document_bytes(path, sample)))
    if file_type == "compound-document" or suffix in {".doc", ".xls", ".ppt", ".msi"}:
        data = read_structured_document_bytes(path, sample)
        findings.extend(scan_ole_content(path, data))
        lowered = data[:MAX_TEXT_SCAN_BYTES].lower()
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
        findings.extend(scan_lnk_content(path, read_structured_document_bytes(path, sample)))
        if not any(finding.rule_id == "shortcut-suspicious-target" for finding in findings):
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
    known_bad_paths.extend(discover_known_bad_artifact_paths(cleanable_hashes))
    known_bad_paths = sorted(set(known_bad_paths), key=lambda item: str(item).lower())
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
                try:
                    shutil.move(str(path), str(destination))
                except PermissionError:
                    if not destination.exists() or path.exists():
                        raise
                write_quarantine_manifest(
                    quarantine_dir,
                    original_path=path,
                    quarantine_path=destination,
                    sha256_value=latest_hash,
                    size=destination.stat().st_size,
                    reason="known-bad-hash",
                    eligible=True,
                )
                report.append(f"Quarantined known-bad file: {path} -> {destination}")
        except Exception as exc:  # noqa: BLE001 - cleanup should report each failure.
            report.append(f"Failed to remove {path}: {type(exc).__name__}: {exc}")

    if platform.system() == "Windows":
        report.extend(remove_known_bad_startup_entries(cleanable_hashes))
    return report


def remove_scan_results(results: list[ScanResult], quarantine_dir: Path, *, delete: bool = False) -> list[str]:
    report: list[str] = []
    file_results = [result for result in results if result.kind == "file"]
    if not file_results:
        return ["No removable file results were selected. Registry, process, archive-entry, and memory findings are informational in this removal view."]
    for result in file_results:
        path = Path(result.path)
        if not path.exists():
            report.append(f"Already gone: {path}")
            continue
        try:
            latest_hash, stable = hash_with_stability_check(path)
            latest_hash = latest_hash.lower()
            if not stable:
                report.append(f"Skipped unstable file, metadata changed while hashing: {path}")
                continue
            if result.sha256 and latest_hash != result.sha256.lower():
                report.append(f"Skipped changed file, hash no longer matches scan result: {path}")
                continue
            if delete:
                path.unlink()
                report.append(f"Deleted selected file: {path}")
            else:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                destination = unique_quarantine_path(quarantine_dir, path, latest_hash)
                try:
                    shutil.move(str(path), str(destination))
                except PermissionError:
                    if not destination.exists() or path.exists():
                        raise
                write_quarantine_manifest(
                    quarantine_dir,
                    original_path=path,
                    quarantine_path=destination,
                    sha256_value=latest_hash,
                    size=destination.stat().st_size,
                    reason="selected-finding",
                    eligible=True,
                )
                report.append(f"Quarantined selected file: {path} -> {destination}")
        except Exception as exc:  # noqa: BLE001
            report.append(f"Failed to remove {path}: {type(exc).__name__}: {exc}")
    return report


def discover_known_bad_artifact_paths(cleanable_hashes: set[str]) -> list[Path]:
    cleanable_hashes = {item.lower() for item in cleanable_hashes}
    wanted_names = {
        name.lower()
        for digest, names in BUILTIN_KNOWN_BAD_FILENAMES.items()
        if digest.lower() in cleanable_hashes
        for name in names
    }
    if not wanted_names:
        return []
    roots: list[Path] = []
    for value in (os.environ.get("USERPROFILE"), os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"), os.environ.get("TEMP"), os.environ.get("TMP")):
        if value:
            roots.append(Path(value))
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        roots.extend([Path(userprofile) / "Downloads", Path(userprofile) / "Desktop", Path(userprofile) / "Documents"])
    found: list[Path] = []
    seen_roots: set[str] = set()
    for root in roots:
        try:
            resolved = str(root.resolve()).lower()
        except OSError:
            continue
        if resolved in seen_roots or not root.exists():
            continue
        seen_roots.add(resolved)
        scanned = 0
        stack = [root]
        while stack and scanned < 20_000:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        scanned += 1
                        if scanned >= 20_000:
                            break
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name.lower() not in DEFAULT_EXCLUDED_DIRS:
                                    stack.append(Path(entry.path))
                                continue
                            if entry.is_file(follow_symlinks=False) and entry.name.lower() in wanted_names:
                                path = Path(entry.path)
                                if sha256_file(path).lower() in cleanable_hashes:
                                    found.append(path)
                        except OSError:
                            continue
            except OSError:
                continue
    return found


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


def write_quarantine_manifest(
    quarantine_dir: Path,
    *,
    original_path: Path,
    quarantine_path: Path,
    sha256_value: str,
    size: int,
    reason: str,
    eligible: bool,
) -> Path:
    manifest = {
        "schema": "cln-quarantine-manifest-v1",
        "cln_version": VERSION,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "original_path": str(original_path),
        "quarantine_path": str(quarantine_path),
        "sha256": sha256_value.lower(),
        "size": size,
        "reason": reason,
        "restore_eligible": eligible,
    }
    manifest_name = f"{sha256_value[:12]}_{int(time.time() * 1000)}.manifest.json"
    manifest_path = quarantine_dir / manifest_name
    secure_write_text_file(manifest_path, json.dumps(manifest, indent=2))
    return manifest_path


def restore_quarantine_manifest(manifest_path: Path) -> list[str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Could not read quarantine manifest: {type(exc).__name__}: {exc}"]
    if manifest.get("schema") != "cln-quarantine-manifest-v1":
        return ["Unsupported quarantine manifest schema."]
    if not manifest.get("restore_eligible", False):
        return ["Manifest says this item is not eligible for restore."]
    quarantine_path = Path(str(manifest.get("quarantine_path") or ""))
    original_path = Path(str(manifest.get("original_path") or ""))
    expected_hash = str(manifest.get("sha256") or "").lower()
    if not quarantine_path.exists():
        return [f"Quarantined file is missing: {quarantine_path}"]
    try:
        current_hash = sha256_file(quarantine_path).lower()
    except OSError as exc:
        return [f"Could not hash quarantined file: {type(exc).__name__}: {exc}"]
    if expected_hash and current_hash != expected_hash:
        return [f"Hash mismatch; refusing restore: expected {expected_hash}, got {current_hash}"]
    if original_path.exists():
        return [f"Original path already exists; refusing to overwrite: {original_path}"]
    try:
        original_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(quarantine_path), str(original_path))
        except PermissionError:
            if original_path.exists() and sha256_file(original_path).lower() == current_hash:
                return [f"Restored quarantined file: {quarantine_path} -> {original_path} (quarantine copy could not be removed automatically)"]
            raise
    except OSError as exc:
        return [f"Restore failed: {type(exc).__name__}: {exc}"]
    return [f"Restored quarantined file: {quarantine_path} -> {original_path}"]


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



def scan_lnk(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if len(data) < 76 or data[:4] != b'\x4c\x00\x00\x00':
        return findings
    
    flags = int.from_bytes(data[20:24], 'little')
    offset = 76
    
    has_target_id_list = bool(flags & 0x01)
    has_link_info = bool(flags & 0x02)
    has_name = bool(flags & 0x04)
    has_rel_path = bool(flags & 0x08)
    has_working_dir = bool(flags & 0x10)
    has_args = bool(flags & 0x20)
    has_icon_loc = bool(flags & 0x40)
    is_unicode = bool(flags & 0x80)

    target = ""
    arguments = ""

    if has_target_id_list:
        if offset + 2 > len(data): return findings
        id_list_size = int.from_bytes(data[offset:offset+2], 'little')
        offset += 2 + id_list_size
    
    if has_link_info:
        if offset + 4 > len(data): return findings
        link_info_size = int.from_bytes(data[offset:offset+4], 'little')
        if offset + 28 <= len(data):
            flags_info = int.from_bytes(data[offset+8:offset+12], 'little')
            local_base_offset = int.from_bytes(data[offset+16:offset+20], 'little')
            if flags_info & 0x01 and offset + local_base_offset < len(data):
                end = data.find(b'\x00', offset + local_base_offset)
                if end == -1: end = len(data)
                target = data[offset+local_base_offset:end].decode('mbcs', errors='replace')
        offset += link_info_size

    def read_string(offset: int) -> tuple[str, int]:
        if offset >= len(data):
            return "", offset
        count = int.from_bytes(data[offset:offset+2], 'little')
        offset += 2
        mult = 2 if is_unicode else 1
        encoding = 'utf-16-le' if is_unicode else 'mbcs'
        end = offset + count * mult
        if end > len(data): end = len(data)
        return data[offset:end].decode(encoding, errors='replace'), end

    if has_name:
        _, offset = read_string(offset)
    if has_rel_path:
        _, offset = read_string(offset)
    if has_working_dir:
        _, offset = read_string(offset)
    if has_args:
        arguments, offset = read_string(offset)
        
    lowered_target = target.lower()
    lowered_args = arguments.lower()
    
    risky_exes = ("powershell", "pwsh", "cmd.exe", "mshta", "rundll32", "wscript", "cscript", "certutil", "bitsadmin")
    if any(exe in lowered_target or exe in lowered_args for exe in risky_exes):
        findings.append(Finding("lnk-suspicious-target", "Shortcut executes a high-risk system tool", "high", f"Target: {target} | Args: {arguments}"))
    elif arguments:
        findings.append(Finding("lnk-has-arguments", "Shortcut has arguments", "low", f"Target: {target} | Args: {arguments}"))

    return findings

def scan_pdf(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if b"/JavaScript" in data or b"/JS" in data:
        findings.append(Finding("pdf-javascript", "PDF contains embedded JavaScript", "medium", "Matches /JavaScript or /JS"))
    if b"/OpenAction" in data or b"/Launch" in data:
        findings.append(Finding("pdf-auto-launch", "PDF contains auto-launch or open actions", "high", "Matches /OpenAction or /Launch"))
    if b"/EmbeddedFiles" in data:
        findings.append(Finding("pdf-embedded-files", "PDF contains embedded files", "medium", "Matches /EmbeddedFiles"))
    if b"/URI" in data:
        urls = re.findall(rb'/URI\s*\((.*?)\)', data)
        for url in urls:
            try:
                decoded = url.decode('utf-8', errors='ignore')
                if re.search(r'(?i)https?://', decoded) and not any(trusted in decoded.lower() for trusted in ('adobe.com', 'microsoft.com')):
                    findings.append(Finding("pdf-external-uri", "PDF contains external URI", "low", decoded))
            except Exception:
                pass
    return findings

def scan_pe(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if len(data) < 64 or data[:2] != b"MZ":
        return findings
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b"PE\0\0":
        return findings
    
    num_sections = int.from_bytes(data[pe_offset+6:pe_offset+8], "little")
    opt_header_size = int.from_bytes(data[pe_offset+20:pe_offset+22], "little")
    sections_offset = pe_offset + 24 + opt_header_size
    
    suspicious_sections = {b".upx", b".vmp", b".themida", b".enigma"}
    
    for i in range(num_sections):
        sec_offset = sections_offset + i * 40
        if sec_offset + 40 > len(data): break
        sec_name = data[sec_offset:sec_offset+8].rstrip(b'\0').lower()
        if any(sec_name.startswith(susp) for susp in suspicious_sections):
            findings.append(Finding("pe-packed-section", "Executable contains known packer section", "high", sec_name.decode('ascii', errors='ignore')))
        
        chars = int.from_bytes(data[sec_offset+36:sec_offset+40], "little")
        if (chars & 0x20000000) and (chars & 0x80000000) and (chars & 0x40000000):
            findings.append(Finding("pe-rwx-section", "Executable contains Read/Write/Execute (RWX) section", "high", sec_name.decode('ascii', errors='ignore')))
    return findings

def scan_ole_vba(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if not data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return findings
    
    if b"VBA" in data or b"vbaProject" in data or b"AutoOpen" in data or b"Document_Open" in data or b"Shell" in data:
        if b"AutoOpen" in data or b"Document_Open" in data or b"AutoExec" in data:
            findings.append(Finding("ole-auto-exec-macro", "OLE Document contains auto-executing macro", "high", "Found AutoOpen/Document_Open strings"))
        else:
            findings.append(Finding("ole-vba-macro", "OLE Document contains VBA macros", "medium", "Found VBA project indicators"))
        
        if b"URLDownloadToFile" in data or b"CreateObject" in data or b"WScript.Shell" in data:
            findings.append(Finding("ole-suspicious-api", "OLE macro contains suspicious API imports", "high", "Found URLDownloadToFile, CreateObject, or WScript.Shell"))
    return findings

def scan_powershell_ast(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    text = data.decode('utf-8', errors='ignore')
    
    if re.search(r'`[a-zA-Z]', text):
        findings.append(Finding("ps-backtick-obfuscation", "PowerShell script uses backtick obfuscation", "medium", "Found backticks splitting strings"))
    if re.search(r'\{[0-9]+\}\s*-[fF]', text):
        findings.append(Finding("ps-format-obfuscation", "PowerShell script uses format string obfuscation", "medium", "Found -f string formatting"))
    if re.search(r'\$\w+\s*\+=\s*[\'"]', text):
        findings.append(Finding("ps-var-split-obfuscation", "PowerShell script builds strings dynamically", "low", "Found variable concatenation"))
    
    import platform, subprocess
    if platform.system() == "Windows" and path.suffix.lower() in {".ps1", ".psm1"} and len(data) < 500_000:
        try:
            script = f"""
            $ErrorActionPreference = 'SilentlyContinue'
            $path = '{path.resolve()}'
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
            $ast.FindAll({{ $args[0] -is [System.Management.Automation.Language.CommandAst] }}, $true) | 
                ForEach-Object {{ $_.GetCommandName() }} | 
                Where-Object {{ $_ -match 'iex|Invoke-Expression|DownloadString|WebClient|WScript.Shell|BitTransfer' }} |
                Select-Object -Unique
            """
            powershell = trusted_windows_executable("WindowsPowerShell", "v1.0", "powershell.exe")
            if powershell:
                completed = subprocess.run([str(powershell), "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=5)
                if completed.stdout.strip():
                    findings.append(Finding("ps-ast-suspicious-command", "PowerShell AST found suspicious command execution", "high", completed.stdout.strip()[:100].replace('\n', ' ')))
        except Exception:
            pass
            
    return findings


def scan_startup_locations() -> list[ScanResult]:
    results: list[ScanResult] = []
    results.extend(scan_startup_folders())
    results.extend(scan_registry_run_keys())
    results.extend(scan_registry_persistence_locations())
    results.extend(scan_registry_value_persistence_locations())
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
            "HKEY_CURRENT_USER",
            winreg.HKEY_CURRENT_USER,
            r"Software\Classes\CLSID",
            "com-hijack-hkcu",
            "Current-user COM class override exists",
        ),
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
        (
            "HKEY_LOCAL_MACHINE",
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "appinit-dlls",
            "AppInit_DLLs injection setting exists",
        ),
        (
            "HKEY_LOCAL_MACHINE",
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
            "appcert-dlls",
            "AppCertDlls process injection setting exists",
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
                    if rule_id == "com-hijack-hkcu":
                        detail = registry_com_server_detail(hive, f"{key_path}\\{subkey_name}")
                        if not detail:
                            continue
                    severity = "high" if suspicious_startup_command(detail) else "medium"
                    if rule_id == "ifeo-debugger" and "debugger" not in detail.lower():
                        continue
                    if rule_id == "appinit-dlls" and "appinit_dlls=" not in detail.lower():
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


def registry_com_server_detail(hive: object, clsid_path: str) -> str:
    details: list[str] = []
    for server_key in ("InprocServer32", "LocalServer32"):
        detail = registry_subkey_default_detail(hive, f"{clsid_path}\\{server_key}")
        if detail:
            details.append(f"{server_key}: {detail}")
    return "; ".join(details)


def scan_registry_value_persistence_locations() -> list[ScanResult]:
    try:
        import winreg
    except ImportError:
        return []
    checks = [
        (
            "HKEY_LOCAL_MACHINE",
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            {"AppInit_DLLs", "LoadAppInit_DLLs"},
            "appinit-dlls",
            "AppInit_DLLs process injection setting exists",
        ),
        (
            "HKEY_LOCAL_MACHINE",
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
            None,
            "appcert-dlls",
            "AppCertDlls process injection setting exists",
        ),
    ]
    results: list[ScanResult] = []
    for hive_name, hive, key_path, names, rule_id, title in checks:
        try:
            with winreg.OpenKey(hive, key_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if names is not None and name not in names:
                        continue
                    value_text = str(value).strip()
                    if not value_text or value_text in {"0", "[]"}:
                        continue
                    result = ScanResult(path=f"{hive_name}\\{key_path}\\{name}", kind="registry")
                    severity = "high" if suspicious_startup_command(value_text) or rule_id == "appcert-dlls" else "medium"
                    result.findings.append(Finding(rule_id, title, severity, value_text))
                    results.append(result)
        except OSError:
            continue
    return results


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
    findings.extend(scan_extension_code(extension_id, manifest_path, manifest))
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


def scan_extension_code(extension_id: str, manifest_path: Path, manifest: dict) -> list[Finding]:
    root = manifest_path.parent
    script_paths: set[Path] = set()
    background = manifest.get("background")
    if isinstance(background, dict):
        service_worker = background.get("service_worker")
        if isinstance(service_worker, str):
            script_paths.add(root / service_worker)
        scripts = background.get("scripts")
        if isinstance(scripts, list):
            script_paths.update(root / str(item) for item in scripts)
    for item in manifest.get("content_scripts", []) if isinstance(manifest.get("content_scripts"), list) else []:
        if isinstance(item, dict) and isinstance(item.get("js"), list):
            script_paths.update(root / str(script) for script in item["js"])
    findings: list[Finding] = []
    for script in sorted(script_paths, key=lambda item: str(item).lower())[:100]:
        try:
            if not path_is_relative_to(script.resolve(), root.resolve()) or not script.is_file() or script.stat().st_size > MAX_ARCHIVE_TEXT_ENTRY_BYTES:
                continue
            data = script.read_bytes()
        except OSError:
            continue
        lowered = data.lower()
        detail = f"id={extension_id}, script={script}"
        if re.search(rb"(?is)\b(?:eval|new\s+Function|importScripts)\b.{0,160}\bhttps?://", data) or b"chrome.tabs.executeScript" in data:
            findings.append(Finding("browser-extension-remote-code", "Browser extension script loads or executes remote code", "high", detail, describe_match(data, 0, min(len(data), 80))))
        if any(token in lowered for token in (b"document.cookie", b"localstorage", b"chrome.cookies", b"authorization", b"bearer")) and any(token in lowered for token in (b"fetch(", b"xmlhttprequest", b"sendbeacon", b"webhook")):
            findings.append(Finding("browser-extension-credential-access", "Browser extension script may access credentials or session data and send it out", "high", detail))
        for finding in scan_content_bytes(data):
            if finding.severity in {"high", "critical"}:
                findings.append(Finding(f"browser-extension-{finding.rule_id}", f"Browser extension script: {finding.title}", finding.severity, detail, finding.evidence, finding.remediation))
    return findings


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


def scan_running_processes() -> list[ScanResult]:
    if platform.system() != "Windows":
        return []
    results = scan_process_command_lines()
    results.extend(scan_process_memory_regions())
    return results


def scan_network_connections() -> list[ScanResult]:
    if platform.system() != "Windows":
        return []
    powershell = trusted_windows_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    if not powershell:
        return []
    script = (
        "$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Select-Object @{n='Protocol';e={'TCP'}},State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess;"
        "$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
        "Select-Object @{n='Protocol';e={'UDP'}},@{n='State';e={'Listen'}},LocalAddress,LocalPort,@{n='RemoteAddress';e={''}},@{n='RemotePort';e={0}},OwningProcess;"
        "@($tcp) + @($udp) | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run([str(powershell), "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=15, check=False)
    except Exception:
        return []
    try:
        data = json.loads(completed.stdout) if completed.stdout.strip() else []
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else [data]
    results: list[ScanResult] = []
    for item in items[:5000]:
        if not isinstance(item, dict):
            continue
        remote = str(item.get("RemoteAddress") or "")
        remote_port = int(item.get("RemotePort") or 0)
        local = str(item.get("LocalAddress") or "")
        local_port = int(item.get("LocalPort") or 0)
        pid = str(item.get("OwningProcess") or "")
        protocol = str(item.get("Protocol") or "TCP")
        state = str(item.get("State") or "")
        findings = network_connection_findings(
            remote,
            remote_port,
            local_address=local,
            local_port=local_port,
            protocol=protocol,
            state=state,
        )
        if not findings:
            continue
        remote_label = f"{remote}:{remote_port}" if remote and remote_port else ""
        local_label = f"{local}:{local_port}" if local_port else local
        result = ScanResult(path=f"network:{pid}:{protocol}:{state}:{local_label}->{remote_label}", kind="network")
        result.findings.extend(findings)
        results.append(result)
    return results


def network_connection_findings(remote: str, port: int, *, local_address: str = "", local_port: int = 0, protocol: str = "TCP", state: str = "") -> list[Finding]:
    findings: list[Finding] = []
    detail = f"{protocol} {state or 'unknown'} local={local_address}:{local_port} remote={remote}:{port}"
    if port in SUSPICIOUS_NETWORK_PORTS or local_port in SUSPICIOUS_NETWORK_PORTS:
        findings.append(Finding("network-suspicious-port", "Network endpoint uses a commonly abused port", "medium", detail))
    elif state.lower() in {"listen", "bound"} or not remote:
        severity = "low" if local_address not in {"127.0.0.1", "::1", "localhost"} else "info"
        findings.append(Finding("network-listening-port", "Local listening port observed", severity, detail))
    else:
        findings.append(Finding("network-active-port", "Active network port observed", "info", detail))
    if remote and is_raw_public_ip(remote):
        findings.append(Finding("network-raw-public-ip", "Active connection uses a raw public IP address", "low", f"{remote}:{port}"))
    return findings


def is_raw_public_ip(value: str) -> bool:
    if not re.fullmatch(r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)", value):
        return False
    return not value.startswith(("10.", "127.", "169.254.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))


def scan_process_command_lines() -> list[ScanResult]:
    powershell = trusted_windows_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    if not powershell:
        return []
    script = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run([str(powershell), "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=15, check=False)
    except Exception:
        return []
    try:
        data = json.loads(completed.stdout) if completed.stdout.strip() else []
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else [data]
    results: list[ScanResult] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name") or "")
        command = str(item.get("CommandLine") or "")
        pid = str(item.get("ProcessId") or "")
        if not command:
            continue
        findings = suspicious_process_command_findings(name, command)
        if findings:
            result = ScanResult(path=f"process:{pid}:{name}", kind="process")
            result.findings.extend(findings)
            results.append(result)
    return results


def suspicious_process_command_findings(name: str, command: str) -> list[Finding]:
    lowered = command.lower()
    exe = name.lower()
    checks = [
        ("lolbin-certutil-download", "certutil downloads or decodes remote content", "certutil" in exe and ("-urlcache" in lowered or "-decode" in lowered or "http://" in lowered or "https://" in lowered)),
        ("lolbin-msbuild-inline-task", "MSBuild loads an inline task or project from user-writable content", "msbuild" in exe and ("codetaskfactory" in lowered or "inline task" in lowered or "appdata" in lowered or "\\temp\\" in lowered)),
        ("lolbin-wmic-process-create", "WMIC creates a process", "wmic" in exe and "process" in lowered and "call" in lowered and "create" in lowered),
        ("lolbin-rundll32-script", "rundll32 launches script or URL handler content", "rundll32" in exe and any(token in lowered for token in ("javascript:", "http://", "https://", "url.dll", "shell32.dll"))),
        ("lolbin-regsvr32-scriptlet", "regsvr32 loads remote or scriptlet content", "regsvr32" in exe and any(token in lowered for token in ("scrobj.dll", "/i:http", "/i:https", ".sct"))),
        ("lolbin-powershell-encoded", "PowerShell runs an encoded command", ("powershell" in exe or "pwsh" in exe) and re.search(r"(?i)(?<!\w)-(?:enc|encodedcommand)(?!\w)", command) is not None),
    ]
    findings = [Finding(rule_id, title, "high", command[:500]) for rule_id, title, matched in checks if matched]
    if not findings and suspicious_startup_command(command):
        findings.append(Finding("process-suspicious-command", "Process command line has suspicious execution indicators", "medium", command[:500]))
    return findings


def scan_process_memory_regions() -> list[ScanResult]:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE = 0x10

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    process_ids = (wintypes.DWORD * 8192)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(process_ids), ctypes.sizeof(process_ids), ctypes.byref(needed)):
        return []
    count = min(needed.value // ctypes.sizeof(wintypes.DWORD), 8192)
    results: list[ScanResult] = []
    for raw_pid in list(process_ids)[:count]:
        pid = int(raw_pid)
        if pid in {0, os.getpid()}:
            continue
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            continue
        try:
            process_name = process_image_name(psapi, handle) or "unknown"
            findings = executable_private_memory_findings(kernel32, handle)
            if findings:
                result = ScanResult(path=f"process-memory:{pid}:{process_name}", kind="process-memory")
                result.findings.extend(findings)
                results.append(result)
        finally:
            kernel32.CloseHandle(handle)
        if len(results) >= 200:
            break
    return results


def process_image_name(psapi: object, handle: object) -> str:
    try:
        import ctypes
    except ImportError:
        return ""
    buffer = ctypes.create_unicode_buffer(1024)
    try:
        length = psapi.GetModuleFileNameExW(handle, None, buffer, len(buffer))
    except Exception:
        return ""
    return buffer.value[:length] if length else ""


def executable_private_memory_findings(kernel32: object, handle: object) -> list[Finding]:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    executable = {0x10, 0x20, 0x40, 0x80}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    findings: list[Finding] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while address < 0x7FFFFFFFFFFF and len(findings) < 8:
        size = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not size:
            break
        protect = int(mbi.Protect) & 0xFF
        if int(mbi.State) == MEM_COMMIT and int(mbi.Type) == MEM_PRIVATE and protect in executable:
            rule_id = "process-rwx-private-memory" if protect in {0x40, 0x80} else "process-executable-private-memory"
            severity = "high" if protect in {0x40, 0x80} else "medium"
            findings.append(Finding(rule_id, "Process has executable private memory region", severity, f"base=0x{int(mbi.BaseAddress or 0):x}, size={format_bytes(int(mbi.RegionSize))}, protect=0x{protect:x}"))
        next_address = int(mbi.BaseAddress or address) + int(mbi.RegionSize or 4096)
        if next_address <= address:
            break
        address = next_address
    return findings


def suspicious_startup_command(value: str) -> bool:
    lowered = value.lower()
    suspicious_bits = ["powershell", "-enc", "wscript", "cscript", "appdata", "temp", "http://", "https://"]
    return sum(bit in lowered for bit in suspicious_bits) >= 2


if __name__ == "__main__":
    sys.exit(main())
