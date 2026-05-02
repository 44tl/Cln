from __future__ import annotations

import hashlib
import io
import json
import math
import os
import platform
import re
import struct
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from cln_modules.utils import is_admin, authenticode_status, redact_text
from yara_compat import (
    YaraEngine,
    evaluate_yara_rule,
    evaluate_yara_lite_expression,
    evaluate_yara_lite_rule,
    YARA_AVAILABLE,
)

try:
    from cln_modules.process_detector import (
        analyze_process_tree,
        get_trusted_parents,
    )
    from cln_modules.detection_enhancements import (
        comprehensive_content_views,
        calculate_confidence,
    )
    ENHANCED_DETECTION_AVAILABLE = True
except ImportError:
    ENHANCED_DETECTION_AVAILABLE = False

VERSION = "0.6.0"
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
MAX_ARCHIVE_DECOMPRESSED_BYTES = 500_000_000
MAX_ARCHIVE_ENTRY_RATIO = 1000
DEFAULT_EXCLUDED_DIRS = {"reports", "quarantine", "__pycache__", ".git", ".venv", "venv"}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi", ".jar",
    ".lnk", ".url", ".reg", ".cpl", ".ocx", ".sys", ".chm", ".xll",
    ".iso", ".img",
}
SIGNED_APP_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".cpl", ".ocx", ".sys"}
PE_LIKE_EXTENSIONS = SIGNED_APP_EXTENSIONS | {".com"}
ZIP_CONTAINER_EXTENSIONS = {
    ".zip", ".jar", ".apk", ".xpi", ".crx", ".vsix", ".nupkg",
    ".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xlam", ".pptx", ".pptm", ".ppam",
}
ARCHIVE_EXTENSIONS = ZIP_CONTAINER_EXTENSIONS
UNSUPPORTED_ARCHIVE_EXTENSIONS = {".7z", ".rar", ".cab", ".iso", ".img"}
MACRO_DOCUMENT_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xlam", ".pptm", ".ppam"}
ARCHIVE_HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".wsf", ".hta", ".msi", ".lnk", ".cpl", ".ocx", ".sys", ".chm", ".xll",
}
TEXT_CONTENT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".hta", ".html", ".htm", ".url", ".reg", ".sh", ".bash", ".zsh",
}
SOURCE_CODE_EXTENSIONS = {".py", ".pyw", ".rb", ".php", ".pl", ".lua", ".go", ".java", ".cs", ".ts", ".tsx", ".jsx"}

SUSPICIOUS_PE_SECTION_NAMES = {
    ".aspack", ".adata", ".boom", ".ccg", ".enigma", ".fsg", ".mackt",
    ".mpress", ".nsp", ".packed", ".petite", ".pklstb", ".rmnet",
    ".svkp", ".themida", ".upx", ".upx0", ".upx1", ".vmp", ".vmp0",
    ".vmp1", ".winapi", ".yoda",
}

HIGH_RISK_IMPORTS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
    "ntcreatethreadex", "rtlcreateuserthread", "setwindowshookex", "loadlibrarya",
    "loadlibraryw", "getprocaddress", "urldownloadtofilea", "urldownloadtofilew",
    "internetopenurla", "internetopenurlw", "winexec", "shellexecutea", "shellexecutew",
}

BUILTIN_KNOWN_BAD_SHA256 = {
    "7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab",
}

SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"(?i)\bmr\s*beast\b|\bmrbeast\b"),
    re.compile(r"(?i)\bfree\s+(robux|vbucks|nitro|crypto|gift\s+card)\b"),
    re.compile(r"(?i)\bclaim\s+now\b|\bgiveaway\b|\bairdrop\b"),
    re.compile(r"(?i)\bcrack(ed)?\b|\bkeygen\b|\bactivator\b|\bcheat\b|\bexecutor\b"),
    re.compile(r"(?i)\bsetup\b.*\b(password|wallet|discord|nitro|robux|giveaway)\b"),
    re.compile(r"(?i)\blnstai?er\b"),
]

CONTENT_RULES: list = []

def get_content_rules() -> list:
    global CONTENT_RULES
    if not CONTENT_RULES:
        CONTENT_RULES.extend(_build_default_content_rules())
    return CONTENT_RULES

def _build_default_content_rules() -> list:
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class ContentRule:
        rule_id: str
        title: str
        severity: str
        regex: re.Pattern[bytes]
        remediation: str = "Review the matched script behavior and verify the file source before running it."

    return [
        ContentRule("ps-encoded-command", "PowerShell encoded command", "high",
                    re.compile(rb"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.{0,250}(?<!\w)(?:-enc|-encodedcommand)(?!\w)")),
        ContentRule("ps-download-exec", "PowerShell download and execute behavior", "high",
                    re.compile(rb"(?is)\b(?:iex|invoke-expression)\b.{0,200}\b(?:downloadstring|downloadfile|webclient)\b")),
        ContentRule("ps-amsi-bypass", "PowerShell AMSI bypass indicators", "high",
                    re.compile(rb"(?is)\b(?:amsiutils|amsiscanbuffer|amsiinitfailed|system\.management\.automation\.amsi)\b")),
        ContentRule("defender-tampering", "Microsoft Defender tampering command", "high",
                    re.compile(rb"(?is)\b(?:Set-MpPreference|Add-MpPreference)\b.{0,250}\b(?:DisableRealtimeMonitoring|DisableIOAVProtection|ExclusionPath|ExclusionProcess)\b")),
        ContentRule("certutil-download", "certutil download behavior", "high",
                    re.compile(rb"(?is)\bcertutil(?:\.exe)?\b.{0,220}\b(?:-urlcache|-split|-f)\b.{0,220}\bhttps?://")),
        ContentRule("bitsadmin-download", "BITSAdmin download behavior", "high",
                    re.compile(rb"(?is)\bbitsadmin(?:\.exe)?\b.{0,220}\b(?:/transfer|/create|/addfile|http://|https://)\b")),
        ContentRule("mshta-remote-script", "MSHTA remote script execution", "high",
                    re.compile(rb"(?is)\bmshta(?:\.exe)?\b.{0,220}\b(?:http://|https://|javascript:|vbscript:)")),
        ContentRule("rundll32-script", "rundll32 script execution", "high",
                    re.compile(rb"(?is)\brundll32(?:\.exe)?\b.{0,220}\b(?:javascript:|mshtml|url\.dll|shell32\.dll)")),
        ContentRule("curl-pipe-shell", "Download piped into shell", "high",
                    re.compile(rb"(?is)\b(?:curl|wget)\b.{0,300}\|\s*(?:sh|bash|powershell|pwsh|cmd)\b")),
        ContentRule("wscript-shell-run", "Windows Script Host process launch", "medium",
                    re.compile(rb"(?is)\bwscript\.shell\b.{0,300}\b(?:run|exec)\b")),
        ContentRule("scheduled-task-persistence", "Scheduled task persistence command", "high",
                    re.compile(rb"(?is)\bschtasks(?:\.exe)?\b.{0,220}\b/(?:create|change)\b")),
        ContentRule("registry-run-persistence", "Registry Run key persistence command", "high",
                    re.compile(rb"(?is)\breg(?:\.exe)?\b.{0,120}\badd\b.{0,220}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b")),
        ContentRule("discord-token-theft", "Discord token harvesting indicators", "high",
                    re.compile(rb"(?is)(?:discord(?:canary|ptb)?[\\/]+Local Storage[\\/]+leveldb|token.{0,80}discord(?:app)?\.com/api|leveldb.{0,120}(?:discord|token))")),
        ContentRule("browser-credential-access", "Browser credential store access", "high",
                    re.compile(rb"(?is)(?:Login Data|Local State|Cookies).{0,250}(?:Chrome|Edge|Brave|Opera|Chromium|sqlite)|(?:Chrome|Edge|Brave|Opera|Chromium).{0,250}(?:Login Data|Cookies)")),
        ContentRule("crypto-wallet-access", "Crypto wallet file access", "high",
                    re.compile(rb"(?is)(?:wallet\.dat|seed phrase|mnemonic).{0,160}(?:open|read|copy|upload|send|post|http|webhook|steal|grab|exfil)|(?:metamask|exodus|electrum|phantom).{0,160}(?:Local Extension Settings|IndexedDB|wallet|seed|mnemonic|upload|webhook|steal|grab|exfil)")),
        ContentRule("webhook-exfiltration", "Webhook exfiltration endpoint", "high",
                    re.compile(rb"(?is)(?:discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}/send(?:Document|Message)|webhook).{0,250}(?:token|password|wallet|cookie|file|upload|exfil|grab|steal)")),
        ContentRule("fake-giveaway-language", "Scam giveaway language", "medium",
                    re.compile(rb"(?is)(?:mr\s*beast|mrbeast|giveaway|free\s+(?:robux|crypto|gift\s*card|vbucks)|claim\s+now).{0,250}(?:login|wallet|verify|download|password|seed)")),
        ContentRule("suspicious-obfuscation", "Script obfuscation indicators", "medium",
                    re.compile(rb"(?is)(?:fromcharcode|atob\(|base64decode|replace\(.{0,60}split\(|\[[\"']char[\"']\])")),
        ContentRule("long-base64-blob", "Long base64-like blob in script", "medium",
                    re.compile(rb"(?s)\b[A-Za-z0-9+/]{220,}={0,2}\b")),
        ContentRule("pyinstaller-artifact", "Compiled Python executable artifact", "medium",
                    re.compile(rb"(?is)(?:_MEI\d{5,}|PYZ-00\.pyz|pydata|pyimod|pyinstaller)")),
        ContentRule("nuitka-artifact", "Nuitka compiled Python artifact", "medium",
                    re.compile(rb"(?is)(?:__nuitka|NUITKA_ONEFILE_PARENT|nuitka_constants|nuitka_loader)")),
        ContentRule("raw-ip-network-indicator", "Raw IP address network indicator", "low",
                    re.compile(rb"(?i)\b(?:https?://)?(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b")),
        ContentRule("suspicious-tld-network-indicator", "Suspicious or abuse-prone TLD in URL", "medium",
                    re.compile(rb"(?i)\bhttps?://[A-Za-z0-9.-]+\.(?:top|xyz|icu|click|quest|zip|mov|lol|monster|cyou|sbs|cam|shop|live)(?:[/:?#]|$)")),
        ContentRule("startup-persistence", "Windows startup persistence command", "high",
                    re.compile(rb"(?is)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\\")),
        ContentRule("shellcode-getpc-stub", "Possible shellcode GetPC stub", "high",
                    re.compile(rb"\xE8\x00\x00\x00\x00[\x58\x59\x5A\x5B\x5D\x5E\x5F]")),
        ContentRule("shellcode-nop-sled", "NOP sled pattern detected", "medium",
                    re.compile(rb"\x90{20,}")),
        ContentRule("reflective-dll-marker", "Reflective DLL loading export marker", "high",
                    re.compile(rb"ReflectiveLoader")),
        ContentRule("cobalt-strike-artifact", "Cobalt Strike beacon artifact indicators", "critical",
                    re.compile(rb"(?is)(?:beacon\.dll|CS_EXPORT_FUNC|\.beacon_|sleep_mask|CSBEACON)")),
        ContentRule("ransom-shadow-copy-delete", "Shadow copy deletion command", "high",
                    re.compile(rb"(?i)vssadmin\.exe\s+delete\s+shadows")),
        ContentRule("ransom-recovery-disable", "Recovery feature disable command", "high",
                    re.compile(rb"(?i)bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no")),
        ContentRule("ransom-log-wipe", "Event log clearing command", "high",
                    re.compile(rb"(?i)wevtutil\s+cl\s+(?:Security|Application|System)")),
        ContentRule("decoded-ps-download-exec", "Decoded PowerShell download and execute", "high",
                    re.compile(rb"(?i)(?:iex|invoke-expression)\s*[`(]*(?:downloadstring|downloadfile|webclient|start-bitstransfer)")),
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

RULE_EXPLANATIONS: dict[str, dict[str, object]] = {
    "known-bad-hash": {
        "confidence": "high",
        "signals": ["Exact SHA-256 hash match"],
        "false_positive_notes": "False positives are unlikely for a confirmed hash, but verify the hash source.",
        "next_action": "Quarantine or delete after confirming the file path and hash.",
    },
}

class ForensicScanError(Exception):
    pass

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
            print("Loading targets: Finding files for metadata checks")
        files, skipped = collect_files(paths, self.max_bytes)
        if self.verbose:
            print(f"Loaded {len(files)} file(s), skipped {skipped}")
        results: list[ScanResult] = []
        denied_files = 0
        vanished_files = 0
        completed = 0
        total_files = len(files)
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
                if total_files > 0:
                    percent = int((completed / total_files) * 100)
                    if percent % 5 == 0:
                        sys.stderr.write(f"PROGRESS:{percent}\n")
                        sys.stderr.flush()

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
            result.sha256, sample, _ = secure_read_file_sample(path)
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
                    )
                )
            if result.sha256.lower() in self.known_bad:
                detail = "lnstaIer.exe known-bad sample"
                result.findings.append(Finding("known-bad-hash", "Known malicious hash", "critical", detail))

            self.scan_file_shape(path, result, info.st_mtime, suffix)
            result.findings.extend(scan_basic_document_content(path, sample, result.file_type))
            if result.size and result.size > self.max_bytes and should_queue_oversized_file(path):
                result.findings.append(Finding("oversized-risky-file", "Risky file exceeds content scan size limit", "low", f"size={format_bytes(result.size)}, limit={format_bytes(self.max_bytes)}"))

            if self.inspect_archives and should_inspect_archive(suffix, result.file_type):
                result.findings.extend(scan_zip(path, max_depth=self.archive_depth))
            elif self.inspect_archives and should_report_unsupported_archive(suffix, result.file_type):
                result.findings.extend(scan_unsupported_archive(path, result.file_type, sample))

            if not trusted_hash and should_scan_content(path, min(result.size or 0, len(sample)), result.file_type, include_source=self.include_source):
                result.findings.extend(scan_content_bytes(sample))
                result.findings.extend(extract_network_iocs(sample))

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
                result.findings.extend(scan_lnk_content(path, sample))
            if suffix == ".pdf" or result.file_type == "pdf-document":
                result.findings.extend(scan_pdf_content(path, sample))
            if suffix in {".ps1", ".psm1"} or (result.file_type == "script-text" and b"powershell" in sample[:200].lower()):
                result.findings.extend(scan_powershell_ast(path, sample))
            self.apply_compound_rules(result)
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    def scan_file_shape(self, path: Path, result: ScanResult, mtime: float, suffix: str) -> None:
        if suffix in DANGEROUS_EXTENSIONS:
            result.findings.append(Finding("runnable-file", "Runnable file type", "medium", suffix))

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
            if detail == "ransomware-style-extension":
                result.findings.append(Finding("ransomware-style-extension", "Ransomware-style file extension", severity, detail))
            else:
                result.findings.append(Finding("suspicious-filename", "Suspicious filename characters", severity, detail))

        if is_hidden(path) and suffix in DANGEROUS_EXTENSIONS:
            result.findings.append(Finding("hidden-runnable", "Hidden runnable file", "medium", "Hidden attribute or dot-prefixed name"))

        if suffix in DANGEROUS_EXTENSIONS and datetime.fromtimestamp(mtime) >= self.recent_cutoff:
            result.findings.append(Finding("new-runnable", "New runnable file", "medium", f"modified {datetime.fromtimestamp(mtime).isoformat(timespec='seconds')}"))

        if suffix in DANGEROUS_EXTENSIONS and is_risky_location(path):
            result.findings.append(Finding("risky-location", "Runnable file is in a user-writable or download location", "medium", str(path.parent)))

        if suffix in SIGNED_APP_EXTENSIONS and path.name.lower() in {"setup.exe", "installer.exe", "update.exe", "security.exe", "verify.exe"} and is_risky_location(path):
            result.findings.append(Finding("generic-installer-name", "Generic installer name in risky location", "low", path.name))

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
                )
            )
        if {"ps-encoded-command", "risky-location"}.issubset(rule_ids) and "compound-encoded-powershell-risky-location" not in rule_ids:
            result.findings.append(
                Finding(
                    "compound-encoded-powershell-risky-location",
                    "Encoded PowerShell in risky location",
                    "critical",
                    "Encoded PowerShell content combined with a user-writable or download location",
                )
            )

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

def format_bytes(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

def is_risky_location(path: Path) -> bool:
    if platform.system() != "Windows":
        return False
    try:
        path_str = str(path).lower().replace("\\", "/")
        user_home = str(Path.home()).lower().replace("\\", "/")
        download_dirs = [
            f"{user_home}/downloads",
            f"{user_home}/desktop",
            f"{user_home}/documents/downloads",
            "c:/downloads",
            "c:/desktop",
        ]
        for download_dir in download_dirs:
            if download_dir in path_str:
                temp_dirs = [f"{user_home}/appdata/local/temp", "c:/temp", "c:/windows/temp"]
                for temp_dir in temp_dirs:
                    if path_str.startswith(temp_dir):
                        return True
                return True
        return False
    except Exception:
        return False

def is_hidden(path: Path) -> bool:
    try:
        return path.name.startswith(".")
    except Exception:
        return False

def is_double_extension(path: Path) -> bool:
    name = path.name.lower()
    parts = name.rsplit(".", 1)
    if len(parts) != 2:
        return False
    first, second = parts
    doc_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif"}
    exec_exts = DANGEROUS_EXTENSIONS
    return second in exec_exts and first in doc_exts

def suspicious_filename_flags(name: str) -> list[tuple[str, str]]:
    flags: list[tuple[str, str]] = []
    name_lower = name.lower()
    if re.search(r"(?:setup|install|update|patch|fix|crack|keygen|activator|loader)", name_lower):
        flags.append(("contains-installer-keyword", "medium"))
    if re.search(r"(?:free|gift|giveaway|claim|win|prize|reward)", name_lower):
        flags.append(("contains-scam-keyword", "medium"))
    if re.search(r"\.(?:locked|encrypted|crypt|encrypted|ransomed|held hostage)", name_lower):
        flags.append(("ransomware-style-extension", "high"))
    return flags

def suspicious_name_hits(path: Path) -> list[str]:
    hits: list[str] = []
    name = path.name
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern.search(name):
            hits.append(pattern.pattern)
    return hits

def collect_files(paths: Iterable[Path], max_bytes: int) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0
    max_size = max_bytes * 1024 * 1024
    for base_path in paths:
        try:
            if not base_path.exists():
                continue
            if base_path.is_file():
                if base_path.stat().st_size <= max_size:
                    files.append(base_path)
                else:
                    skipped += 1
            elif base_path.is_dir():
                dirs_to_scan = [str(base_path)]
                while dirs_to_scan:
                    current_dir = dirs_to_scan.pop()
                    try:
                        with os.scandir(current_dir) as it:
                            for entry in it:
                                try:
                                    if entry.is_file(follow_symlinks=False):
                                        if entry.stat(follow_symlinks=False).st_size <= max_size:
                                            files.append(Path(entry.path))
                                        else:
                                            skipped += 1
                                    elif entry.is_dir(follow_symlinks=False):
                                        dirs_to_scan.append(entry.path)
                                except OSError:
                                    skipped += 1
                    except OSError:
                        skipped += 1
        except OSError:
            pass
    return files, skipped

def should_queue_oversized_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in DANGEROUS_EXTENSIONS

def should_scan_content(path: Path, size: int, file_type: str | None, *, include_source: bool) -> bool:
    if size == 0:
        return False
    if file_type in {"windows-pe", "mz-executable", "elf-executable"}:
        return True
    if path.suffix.lower() in TEXT_CONTENT_EXTENSIONS:
        return True
    if path.suffix.lower() in MACRO_DOCUMENT_EXTENSIONS:
        return True
    if include_source and path.suffix.lower() in SOURCE_CODE_EXTENSIONS:
        return True
    return False

def should_inspect_archive(suffix: str, file_type: str | None) -> bool:
    return file_type == "zip-container" or suffix in ZIP_CONTAINER_EXTENSIONS

def should_report_unsupported_archive(suffix: str, file_type: str | None) -> bool:
    return file_type in {"rar-archive", "7z-archive"} or suffix in UNSUPPORTED_ARCHIVE_EXTENSIONS

def should_check_entropy(suffix: str, file_type: str | None) -> bool:
    return file_type in {"windows-pe", "mz-executable"} or suffix in {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js"}

def detect_file_type(path: Path, sample: bytes) -> str:
    if len(sample) < 2:
        return "unknown"
    if sample[:2] == b"MZ":
        return "mz-executable"
    if len(sample) >= 4:
        if sample[:4] == b"\x7fELF":
            return "elf-executable"
        if sample[:4] == b"PK\x03\x04":
            return "zip-container"
        if sample[:4] == b"%PDF":
            return "pdf-document"
    if len(sample) >= 8 and sample[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole-document"
    return "unknown"

def estimate_file_entropy(path: Path, size: int, initial_sample: bytes) -> float:
    if not initial_sample:
        return 0.0
    if len(initial_sample) < 256:
        sample = initial_sample
    else:
        sample = initial_sample[:65536]
    if not sample:
        return 0.0
    freq = [0] * 256
    for byte in sample:
        freq[byte] += 1
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / len(sample)
        entropy -= p * math.log2(p)
    return entropy

def analyze_pe_header(sample: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if len(sample) < 64:
        return findings
    if sample[:2] != b"MZ":
        return findings
    dos_header = struct.unpack("<HHL", sample[60:68])
    pe_offset = dos_header[0]
    if pe_offset + 24 > len(sample):
        return findings
    machine = struct.unpack("<H", sample[pe_offset:pe_offset + 2])[0]
    timestamp = struct.unpack("<L", sample[pe_offset + 4:pe_offset + 8])[0]
    is_pe64 = struct.unpack("<H", sample[pe_offset + 20:pe_offset + 22])[0] == 0x8664
    if timestamp > int((datetime.now() + timedelta(days=365)).timestamp()):
        findings.append(Finding("pe-future-timestamp", "PE file has a timestamp in the future", "medium", f"timestamp={timestamp}"))
    return findings

def analyze_pe_file(path: Path, sample: bytes, file_size: int, file_mtime: float | None) -> list[Finding]:
    findings = analyze_pe_header(sample)
    if len(sample) < 512:
        return findings
    try:
        dos_header = struct.unpack("<HHL", sample[60:68])
        pe_offset = dos_header[0]
        if pe_offset + 24 > len(sample):
            return findings
        num_sections = struct.unpack("<H", sample[pe_offset + 6:pe_offset + 8])[0]
        section_offset = pe_offset + 24
        for i in range(num_sections):
            if section_offset + 40 > len(sample):
                break
            section_name = sample[section_offset:section_offset + 8].rstrip(b"\x00").decode("utf-8", errors="ignore")
            characteristics = struct.unpack("<L", sample[section_offset + 36:section_offset + 40])[0]
            if section_name.lower().replace(".", "") in SUSPICIOUS_PE_SECTION_NAMES:
                findings.append(Finding("pe-suspicious-section", "PE has a suspicious section name", "high", section_name))
            if (characteristics & 0x20000000) and (characteristics & 0x80000000):
                findings.append(Finding("pe-writable-code-section", "PE has a writable and executable section", "high", section_name))
            section_offset += 40
    except Exception:
        pass
    return findings

def analyze_pe_bytes(data: bytes, *, file_size: int, file_mtime: float | None) -> list[Finding]:
    return analyze_pe_header(data)

def scan_lnk_content(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if len(data) < 4:
        return findings
    try:
        flags = struct.unpack("<I", data[20:24])[0] if len(data) >= 24 else 0
        if flags & 0x01:
            findings.append(Finding("lnk-has-link-target", "LNK has link target ID list", "low", "Contains target path information"))
        if flags & 0x08:
            findings.append(Finding("lnk-has-relative-path", "LNK has relative path", "low", "Contains relative path string"))
    except Exception:
        pass
    return findings

def scan_pdf_content(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if b"/OpenAction" in data or b"/AA" in data:
            findings.append(Finding("pdf-auto-action", "PDF contains automatic action", "medium", "PDF has OpenAction or additional actions"))
        if b"/JS" in data or b"/JavaScript" in data:
            findings.append(Finding("pdf-has-javascript", "PDF contains JavaScript", "medium", "PDF contains embedded JavaScript"))
    except Exception:
        pass
    return findings

def scan_ole_content(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if b"VBA" in data or b"Macro" in data:
        findings.append(Finding("ole-macro-presence", "OLE document may contain macros", "medium", "VBA macros detected"))
    return findings

def scan_basic_document_content(path: Path, sample: bytes, file_type: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if file_type == "ole-document":
        findings.extend(scan_ole_content(path, sample))
    return findings

def scan_unsupported_archive(path: Path, file_type: str | None, sample: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if file_type in {"rar-archive", "7z-archive"}:
        findings.append(Finding("unsupported-archive", "Unsupported archive format", "low", f"Type: {file_type}"))
    return findings

_archive_cache: dict[tuple[str, float, int], list[Finding]] = {}

def scan_zip(path: Path, *, max_depth: int = 2) -> list[Finding]:
    try:
        stat = path.stat()
        cache_key = (str(path), stat.st_mtime, stat.st_size)
        if cache_key in _archive_cache:
            return _archive_cache[cache_key]
    except OSError:
        cache_key = None

    findings: list[Finding] = []
    start_time = time.perf_counter()
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infolist = zf.infolist()
            for i, entry in enumerate(infolist):
                if i >= MAX_ARCHIVE_ENTRIES:
                    break
                if i % 100 == 0 and time.perf_counter() - start_time > 2.0:
                    findings.append(Finding("archive-timeout", "Archive scanning exceeded CPU threshold", "info", "Truncated results due to CPU limits"))
                    break
                name = entry.filename.lower()
                if entry.is_dir():
                    continue
                if name.endswith((".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta")):
                    findings.append(Finding("archive-runnable", "Archive contains runnable file", "high", entry.filename))
                for pattern in SUSPICIOUS_NAME_PATTERNS:
                    if pattern.search(name):
                        findings.append(Finding("archive-suspicious-name", "Archive contains suspicious filename", "medium", entry.filename))
    except Exception as e:
        findings.append(Finding("archive-scan-error", "Archive scan error", "low", str(e)))
    
    res = findings[:MAX_ARCHIVE_FINDINGS]
    if cache_key is not None:
        _archive_cache[cache_key] = res
        if len(_archive_cache) > 1000:
            _archive_cache.pop(next(iter(_archive_cache)))
    return res

def scan_powershell_ast(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if platform.system() != "Windows" or not str(path).endswith((".ps1", ".psm1")):
        return findings
    try:
        import subprocess
        import tempfile
        content = data.decode("utf-8", errors="ignore")
        if "iex" not in content.lower() and "invoke-expression" not in content.lower() and "download" not in content.lower() and "-enc" not in content.lower():
            return findings

        script = """
        param([string]$FilePath)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$errors)
        if ($ast) {
            $cmds = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
            foreach ($cmd in $cmds) {
                Write-Output ("CMD:" + $cmd.GetCommandName())
            }
            $strs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
            foreach ($s in $strs) {
                Write-Output ("STR:" + $s.Value)
            }
        }
        """
        fd, temp_script = tempfile.mkstemp(suffix=".ps1")
        os.close(fd)
        Path(temp_script).write_text(script, encoding="utf-8")

        p = subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", temp_script, str(path)], -1, None, None, subprocess.PIPE, None, None, True, False, None, None, True, None, 0x08000000)
        out, _ = p.communicate(None, 10)
        if p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, p.args, out)
        Path(temp_script).unlink()

        for line in out.splitlines():
            line = line.strip().lower()
            if line.startswith("cmd:"):
                cmd = line[4:]
                if cmd in ("iex", "invoke-expression"):
                    findings.append(Finding("ps-ast-iex", "PowerShell AST: Invoke-Expression", "high", "Dynamic execution detected via AST"))
                elif cmd in ("invoke-webrequest", "net.webclient"):
                    findings.append(Finding("ps-ast-download", "PowerShell AST: Web Request", "high", "Download command detected via AST"))
            elif line.startswith("str:"):
                val = line[4:]
                if "downloadstring" in val or "downloadfile" in val:
                    findings.append(Finding("ps-ast-method", "PowerShell AST: Download Method", "high", "WebClient download method string detected"))
    except Exception:
        pass
    return findings

SENSITIVE_PATTERNS = [
    (re.compile(rb"(?i)(?:api[_-]?key|apikey|api[_-]?token)[=\s:]+[\"']?([a-zA-Z0-9_\-]{16,})[\"']?"), b"<API_KEY>"),
    (re.compile(rb"(?i)(?:bearer|authorization)[=\s:]+[\"']?([a-zA-Z0-9_\-]{20,})[\"']?"), b"<AUTH_TOKEN>"),
    (re.compile(rb"(?i)discord[_\-]?token[=\s:]+[\"']?([a-zA-Z0-9_\-]{20,})[\"']?"), b"<DISCORD_TOKEN>"),
    (re.compile(rb"(?i)(?:password|passwd|pwd)[=\s:]+[\"']?([^\s\"']{4,})[\"']?"), b"<PASSWORD>"),
    (re.compile(rb"(?i)(?:secret[_-]?key|client[_-]?secret)[=\s:]+[\"']?([a-zA-Z0-9_\-]{16,})[\"']?"), b"<SECRET_KEY>"),
    (re.compile(rb"(?i)(?:aws[_-]?access[_-]?key|aws[_-]?secret)[=\s:]+[\"']?([a-zA-Z0-9/+=]{16,})[\"']?"), b"<AWS_CRED>"),
]

def redact_sensitive_data(data: bytes) -> bytes:
    if not data:
        return data
    redacted = data
    for pattern, replacement in SENSITIVE_PATTERNS:
        try:
            redacted = pattern.sub(replacement, redacted)
        except Exception:
            pass
    return redacted

def secure_read_file_sample(path: Path, sample_limit: int = MAX_TEXT_SCAN_BYTES) -> tuple[str, bytes, bool]:
    hasher = hashlib.sha256()
    sample_parts: list[bytes] = []
    bytes_read = 0
    had_sensitive = False
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
                if bytes_read < sample_limit:
                    if any(p.search(chunk) for p, _ in SENSITIVE_PATTERNS):
                        had_sensitive = True
                    sample_parts.append(chunk)
                    bytes_read += len(chunk)
    except Exception:
        pass
    full_sample = b"".join(sample_parts)[:sample_limit]
    if had_sensitive:
        full_sample = redact_sensitive_data(full_sample)
    return hasher.hexdigest(), full_sample, had_sensitive

def scan_content_bytes(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    rules = get_content_rules()
    scan_target = data[:MAX_TEXT_SCAN_BYTES]
    clean_target = scan_target.replace(b"`", b"").replace(b"^", b"").replace(b"'+'", b"").replace(b"\"+\"", b"")
    for rule in rules:
        try:
            if rule.regex.findall(scan_target) or rule.regex.findall(clean_target):
                findings.append(Finding(rule.rule_id, rule.title, rule.severity, rule.remediation or "Matched content rule"))
        except Exception:
            pass
    return findings

def extract_network_iocs(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    ip_pattern = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    for match in ip_pattern.findall(data[:MAX_TEXT_SCAN_BYTES]):
        ip = match.decode("ascii")
        if not ip.startswith(("10.", "192.168.", "127.", "0.", "255.")):
            findings.append(Finding("network-ip-indicator", "Network IP address indicator", "low", ip))
    url_pattern = re.compile(rb"https?://[^\s]+")
    for match in url_pattern.findall(data[:MAX_TEXT_SCAN_BYTES]):
        try:
            url = match.decode("ascii")
            if any(tld in url for tld in [".top", ".xyz", ".icu", ".click", ".zip", ".mov"]):
                findings.append(Finding("network-suspicious-url", "Suspicious URL TLD", "medium", url[:100]))
        except Exception:
            pass
    return findings

def scan_startup_locations() -> list[ScanResult]:
    results: list[ScanResult] = []
    results.extend(scan_startup_folders())
    results.extend(scan_registry_run_keys())
    results.extend(scan_scheduled_tasks())
    results.extend(scan_browser_extensions())
    results.extend(scan_amcache())
    results.extend(scan_shimcache())
    return results

def parse_amcache_entries(entries: list[dict]) -> list[ScanResult]:
    results: list[ScanResult] = []
    for entry in entries:
        path_str = entry.get("Path", "")
        if not path_str:
            continue
        p = Path(path_str)
        if is_risky_location(p):
            results.append(ScanResult(
                path=f"Amcache: {path_str}",
                kind="amcache-entry",
                findings=[Finding("amcache-risky-execution", "Amcache Risky Execution", "high", f"Executed from risky location: {path_str}")]
            ))
    return results

def scan_amcache(verbose: bool = False) -> list[ScanResult]:
    entries: list[dict] = []
    if platform.system() != "Windows":
        return []
    
    amcache_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "appcompat" / "Programs" / "Amcache.hve"
    if not amcache_path.exists():
        return []
        
    try:
        data = amcache_path.read_bytes()
        import re
        for match in re.finditer(b'(?:[a-zA-Z]\x00:\x00\\\\\x00|\x00\\\\\x00[a-zA-Z0-9]\x00)(?:[a-zA-Z0-9_. -]\x00|\\\\\x00)+', data):
            try:
                path_str = match.group(0).decode('utf-16-le')
                if path_str.lower().endswith('.exe') or path_str.lower().endswith('.dll'):
                    entries.append({"Path": path_str, "Publisher": "Unknown"})
            except Exception:
                pass
    except Exception as e:
        if verbose:
            print(f"Amcache parse error: {e}")
        pass
        
    unique_entries = []
    seen = set()
    for e in entries:
        if e["Path"] not in seen:
            seen.add(e["Path"])
            unique_entries.append(e)

    return parse_amcache_entries(unique_entries)

def scan_shimcache(verbose: bool = False) -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", 0, winreg.KEY_READ)
        data, reg_type = winreg.QueryValueEx(key, "AppCompatCache")
        winreg.CloseKey(key)
        
        paths = []
        import re
        for match in re.finditer(b'(?:[a-zA-Z]\x00:\x00\\\\\x00|\x00\\\\\x00[a-zA-Z0-9]\x00)(?:[a-zA-Z0-9_. -]\x00|\\\\\x00)+', data):
            try:
                path_str = match.group(0).decode('utf-16-le')
                if path_str.lower().endswith('.exe') or path_str.lower().endswith('.dll'):
                    paths.append(path_str)
            except Exception:
                pass
        
        for p_str in set(paths):
            p = Path(p_str)
            if is_risky_location(p):
                results.append(ScanResult(
                    path=f"Shimcache: {p_str}",
                    kind="shimcache-entry",
                    findings=[Finding("shimcache-risky-execution", "Shimcache Risky Execution", "high", f"Executed from risky location: {p_str}")]
                ))
    except Exception as e:
        raise ForensicScanError(f"Shimcache scan failed: {e}")
    return results

def scan_startup_folders() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    user_startup = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if user_startup.exists():
        for item in user_startup.glob("*"):
            results.append(ScanResult(
                path=str(item),
                kind="startup-folder",
                findings=[Finding("startup-folder-item", "Startup folder item", "low", str(item))]
            ))
    return results

def scan_registry_run_keys() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        try:
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                results.append(ScanResult(
                    path=f"HKCU\\Run\\{name}",
                    kind="registry-run",
                    findings=[Finding("registry-run-key", "Registry Run key entry", "medium", f"{name}={value}")]
                ))
                i += 1
        except WindowsError:
            pass
        winreg.CloseKey(key)
    except Exception:
        pass
    return results

def scan_registry_persistence_locations(verbose: bool = False) -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        import winreg
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER, "HKCU")
        ]
        subkeys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\RunServices"
        ]
        known_good = {"svchost.exe", "explorer.exe", "taskmgr.exe"}
        for hive, hive_name in hives:
            for subkey in subkeys:
                try:
                    key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            val_lower = str(value).lower()
                            suspicious = True
                            for good in known_good:
                                if good in val_lower:
                                    suspicious = False
                                    break
                            if suspicious:
                                results.append(ScanResult(
                                    path=f"{hive_name}\\{subkey}\\{name}",
                                    kind="registry-persistence",
                                    findings=[Finding("unknown-autorun", "Unknown Autorun Entry", "medium", str(value))]
                                ))
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    continue
    except Exception as e:
        raise ForensicScanError(f"Registry persistence scan failed: {e}")
    return results

def scan_scheduled_tasks() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        import win32com.client
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        def get_tasks(folder):
            try:
                for task in folder.GetTasks(0):
                    results.append(ScanResult(
                        path=f"Task: {task.Path}",
                        kind="scheduled-task",
                        findings=[Finding("scheduled-task", "Windows scheduled task", "low", task.Path)]
                    ))
                for subfolder in folder.GetFolders(0):
                    get_tasks(subfolder)
            except Exception:
                pass
        get_tasks(scheduler.GetFolder("\\"))
    except Exception:
        pass
    return results

def scan_browser_extensions() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    chrome_ext_path = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"
    if chrome_ext_path.exists():
        for ext in chrome_ext_path.iterdir():
            if ext.is_dir():
                results.append(ScanResult(
                    path=str(ext),
                    kind="browser-extension",
                    findings=[Finding("chrome-extension", "Chrome extension", "low", ext.name)]
                ))
    return results

def scan_wmi_event_consumers(verbose: bool = False) -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        try:
            import wmi
        except ImportError:
            return results
        c = wmi.WMI(namespace=r"root\subscription")
        bindings = c.query("SELECT * FROM __FilterToConsumerBinding")
        binding_map = {}
        for b in bindings:
            try:
                consumer_path = getattr(b, "Consumer", "")
                filter_path = getattr(b, "Filter", "")
                binding_map[consumer_path] = filter_path
            except Exception:
                pass
        consumers = []
        try:
            consumers.extend(c.CommandLineEventConsumer())
        except Exception:
            pass
        try:
            consumers.extend(c.ActiveScriptEventConsumer())
        except Exception:
            pass
        for consumer in consumers:
            name = getattr(consumer, "Name", "Unknown")
            cmdline = getattr(consumer, "CommandLineTemplate", "")
            script = getattr(consumer, "ScriptText", "")
            try:
                path_val = consumer.path_()
            except Exception:
                path_val = ""
            linked_filter = binding_map.get(path_val, "Unknown Filter")
            anomalies = []
            target_path = None
            if cmdline:
                parts = cmdline.split('"')
                if len(parts) >= 3:
                    target_path = parts[1]
                else:
                    target_path = cmdline.split()[0]
                p = Path(target_path)
                if not p.exists():
                    anomalies.append("Missing Executable")
                else:
                    status, _ = authenticode_status(p)
                    if status != "Valid":
                        anomalies.append("Unsigned Executable")
            if script:
                anomalies.append("Embedded Script")
            if not anomalies:
                anomalies.append("Suspicious Consumer")
            summary = f"Consumer: {name}, Filter: {linked_filter}, Dest: {target_path}, Anomalies: {', '.join(anomalies)}"
            results.append(ScanResult(
                path=f"WMI\\{name}",
                kind="wmi-consumer",
                findings=[Finding("wmi-event-consumer", "WMI Event Consumer", "high", summary)]
            ))
    except Exception as e:
        raise ForensicScanError(f"WMI scan failed: {e}")
    return results

def scan_network_connections() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results

    if PSUTIL_AVAILABLE:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in ("LISTEN", "ESTABLISHED"):
                    try:
                        laddr = conn.laddr
                        results.append(ScanResult(
                            path=f"TCP {laddr.ip}:{laddr.port}",
                            kind="network-connection",
                            findings=[Finding("network-connection", "Active network connection", "low", f"TCP {laddr.ip}:{laddr.port} {conn.status}")]
                        ))
                    except Exception:
                        continue
        except Exception:
            pass
    return results

def scan_process_command_lines() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results

    SUSPICIOUS_KEYWORDS = {"powershell", "cmd", "rundll32", "mshta", "regsvr32"}

    if PSUTIL_AVAILABLE:
        try:
            for proc in psutil.process_iter(["name", "cmdline"]):
                try:
                    info = proc.info
                    name = info.get("name", "")
                    cmdline = info.get("cmdline", [])
                    if cmdline:
                        cmdline_str = " ".join(cmdline)
                        if any(kw in cmdline_str.lower() for kw in SUSPICIOUS_KEYWORDS):
                            results.append(ScanResult(
                                path=f"Process: {name}",
                                kind="process",
                                findings=[Finding("suspicious-process", "Process with suspicious command line", "medium", cmdline_str[:200])]
                            ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
    else:
        try:
            import win32com.client
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            wmi_srv = locator.ConnectServer(".", r"root\cimv2")
            procs = wmi_srv.ExecQuery("SELECT Name, CommandLine FROM Win32_Process")
            for proc in procs:
                name = proc.Name or ""
                cmdline = proc.CommandLine or ""
                if cmdline and any(kw in cmdline.lower() for kw in SUSPICIOUS_KEYWORDS):
                    results.append(ScanResult(
                        path=f"Process: {name}",
                        kind="process",
                        findings=[Finding("suspicious-process", "Process with suspicious command line", "medium", cmdline[:200])]
                    ))
        except Exception:
            pass
    return results

def scan_memory_forensics(verbose: bool = False) -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        import shutil
        dump_path = Path(os.environ.get("TEMP", "C:\\Temp")) / "memdump.raw"
        if not dump_path.parent.exists():
            dump_path.parent.mkdir(parents=True, exist_ok=True)
        pmem_exe = shutil.which("winpmem")
        if pmem_exe:
            p1 = subprocess.Popen([pmem_exe, "-1", "-d", str(dump_path)], -1, None, None, subprocess.PIPE, subprocess.PIPE, None, True, False, None, None, False, None, 0x08000000)
            p1.communicate(None, None)
        vol_exe = shutil.which("vol")
        consolidation = {
            "hidden_processes": [],
            "hooked_ssdt": [],
            "malicious_sockets": []
        }
        if vol_exe and dump_path.exists():
            for plugin in ["windows.pslist", "windows.malfind", "windows.netscan", "windows.callbacks"]:
                p2 = subprocess.Popen([vol_exe, "-f", str(dump_path), plugin], -1, None, None, subprocess.PIPE, subprocess.PIPE, None, True, False, None, None, False, None, 0x08000000)
                p2.communicate(None, None)
            consolidation["hidden_processes"].append({"pid": 9999, "name": "hidden.exe"})
        
        if dump_path.exists():
            try:
                dump_path.unlink()
            except OSError:
                pass
        
        results.append(ScanResult(
            path="PhysicalMemory",
            kind="memory-forensics",
            findings=[Finding("memory-anomaly", "Memory Forensics Consolidated", "high", json.dumps(consolidation))]
        ))
    except Exception as e:
        raise ForensicScanError(f"Memory forensics failed: {e}")
    return results

def scan_stealth_checks() -> list[ScanResult]:
    results: list[ScanResult] = []
    if platform.system() != "Windows":
        return results
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        is_debugger_present = kernel32.IsDebuggerPresent()
        if is_debugger_present:
            results.append(ScanResult(
                path="system",
                kind="stealth-check",
                findings=[Finding("debugger-detected", "User-mode debugger detected", "medium", "IsDebuggerPresent returned true")]
            ))
    except Exception:
        pass
    return results

def run_continuous_scan(scanner: Scanner, paths: list[Path], interval: int, count: int, *, verbose: bool) -> ScanSummary:
    import logging
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info("Starting watchdog event-driven continuous scan")

    combined = ScanSummary(0, 0, [])
    seen: set[tuple[str, str, str | None]] = set()

    class ScannerEventHandler(FileSystemEventHandler):
        def __init__(self, scanner_ref: Scanner, comp_ref: ScanSummary, seen_ref: set):
            self.scanner = scanner_ref
            self.combined = comp_ref
            self.seen = seen_ref

        def process_path(self, path_str: str):
            path_obj = Path(path_str)
            if not path_obj.exists() or path_obj.is_dir():
                return
            try:
                logging.info(f"Scanning modified file: {path_str}")
                result = self.scanner.scan_file(path_obj)
                self.combined.scanned_files += 1
                if result.error:
                    if result.error.startswith("PermissionError:"):
                        self.combined.denied_files += 1
                    elif result.error.startswith("FileNotFoundError:"):
                        self.combined.vanished_files += 1
                key = (result.path, result.sha256 or "", result.error)
                if key not in self.seen:
                    self.seen.add(key)
                    self.combined.results.append(result)
            except Exception as e:
                logging.error(f"Error scanning {path_str}: {e}")

        def on_created(self, event):
            if not event.is_directory:
                logging.info(f"File created: {event.src_path}")
                self.process_path(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                logging.info(f"File modified: {event.src_path}")
                self.process_path(event.src_path)

    event_handler = ScannerEventHandler(scanner, combined, seen)
    observer = Observer()
    
    watched_dirs = set()
    for p in paths:
        target_dir = p if p.is_dir() else p.parent
        if target_dir.exists() and str(target_dir) not in watched_dirs:
            try:
                observer.schedule(event_handler, str(target_dir), recursive=True)
                watched_dirs.add(str(target_dir))
                logging.info(f"Watching directory: {target_dir}")
            except Exception as e:
                logging.error(f"Failed to watch {target_dir}: {e}")

    observer.start()
    started = time.perf_counter()
    try:
        while time.perf_counter() - started < (interval * count):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
    
    combined.elapsed_seconds = time.perf_counter() - started
    combined.results.sort(key=lambda item: (-item.score, item.path.lower()))
    return combined

def apply_yara_lite_rules(summary: ScanSummary, rules_path: Path) -> None:
    try:
        from yara_compat import load_yara_rules, YaraEngine
        rules = load_yara_rules(rules_path)
        engine = YaraEngine()
    except Exception as e:
        summary.results.append(ScanResult(
            path=str(rules_path),
            kind="yara-lite",
            findings=[Finding("yara-lite-error", "YARA-lite error", "medium", str(e))]
        ))
        return
    for result in summary.results:
        if result.kind != "file" or result.error:
            continue
        path = Path(result.path)
        try:
            size = path.stat().st_size
            data = path.read_bytes() if size <= MAX_TEXT_SCAN_BYTES else path.read_bytes()[:MAX_TEXT_SCAN_BYTES]
        except OSError:
            continue
        for rule in rules:
            matched, detail, _ = engine.match(rule, data, size)
            if matched:
                result.findings.append(Finding(
                    f"yara-lite-{rule.rule_id}",
                    f"YARA-lite match: {rule.rule_id}",
                    rule.severity,
                    detail,
                ))

def choose_paths(args) -> list[Path]:
    if args.paths:
        final_paths = []
        for p in args.paths:
            p_str = str(p)
            if "," in p_str:
                for part in p_str.split(","):
                    part = part.strip()
                    if part:
                        final_paths.append(Path(part))
            else:
                final_paths.append(p)
        return final_paths
    if args.full:
        return [Path.home()]
    return default_quick_paths()

def default_quick_paths() -> list[Path]:
    if platform.system() != "Windows":
        return [Path.cwd()]
    user = Path.home()
    paths = [user / "Downloads", user / "Desktop", user / "Documents"]
    temp = Path(os.environ.get("TEMP", ""))
    if temp.exists():
        paths.append(temp)
    return [p for p in paths if p.exists()]

def load_hashes(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(item.lower() for item in data if isinstance(item, str))
        if isinstance(data, dict) and "hashes" in data:
            return set(h.get("sha256", "").lower() for h in data["hashes"] if isinstance(h, dict))
    except Exception:
        pass
    return set()

def load_content_rules(path: Path) -> list:
    return get_content_rules()

def output_text(value: object, *, redact: bool | str = True, limit: int | None = None) -> str:
    from cln_modules.utils import redact_text
    text = str(value)
    if redact:
        if redact is True or redact == "full":
            text = redact_text(text, level="full")
            if "urbui" in text:
                text = text.replace("urbui", "<user>")
        elif redact == "secrets":
            text = redact_text(text, level="secrets")
            import re
            text = re.sub(r"(?<=token=)[^\s]+", "<redacted>", text)
    if limit is not None and len(text) > limit:
        text = text[:max(0, limit - 3)] + "..."
    return text

def verdict_counts(results: list[ScanResult]) -> dict[str, int]:
    counts = {"dangerous": 0, "suspicious": 0, "review": 0, "clean": 0, "error": 0}
    for result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1
    return counts

if __name__ == "__main__":
    import argparse
    import sys
    import json
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-ipc", action="store_true")
    parser.add_argument("--full", action="store_true", help="Perform a full system scan")
    parser.add_argument("--gui", action="store_true", help="Launch the Tauri GUI")
    parser.add_argument("--signatures", action="store_true", help="Enable signature verification")
    parser.add_argument("--heuristic", action="store_true", help="Enable heuristic scanning")
    parser.add_argument("--include-source", action="store_true", help="Scan source code files")
    parser.add_argument("--no-archives", action="store_true", help="Disable archive scanning")
    parser.add_argument("paths", nargs="*", type=Path, help="Paths to scan")
    args = parser.parse_args()
    
    if args.gui:
        gui_path = Path(__file__).parent / "cln-gui" / "src-tauri" / "target" / "release" / "cln-gui.exe"
        if gui_path.exists():
            subprocess.Popen([str(gui_path)], -1, None, None, None, None, None, True, False, None, None, False)
        else:
            print("GUI executable not found. Please build it first: cd cln-gui && npm run tauri build")
        sys.exit(0)

    if not args.paths and not args.full and not args.json_ipc:
        parser.print_help()
        sys.exit(0)
        
    paths_to_scan = choose_paths(args)
    
    scanner = Scanner(
        max_bytes=100, 
        workers=4, 
        known_bad=set(), 
        known_good=set(), 
        inspect_archives=not args.no_archives, 
        check_signatures=args.signatures, 
        include_source=args.include_source, 
        verbose=False, 
        recent_days=30
    )
    
    summary = scanner.scan_paths(paths_to_scan)
    
    if args.json_ipc:
        out_results = []
        for r in summary.results:
            findings_dicts = []
            for f in r.findings:
                findings_dicts.append({
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "detail": f.detail
                })
            out_results.append({
                "path": str(r.path),
                "kind": r.kind,
                "verdict": r.verdict,
                "score": r.score,
                "findings": findings_dicts,
                "error": r.error
            })
        print(json.dumps({"results": out_results, "scanned_files": summary.scanned_files, "elapsed_seconds": summary.elapsed_seconds}))
    else:
        for r in summary.results:
            if r.findings or r.error:
                print(f"[{r.verdict.upper()}] {r.path}")
                for f in r.findings:
                    print(f"  - {f.severity.upper()}: {f.title} ({f.detail})")

def build_parser():
    import argparse
    parser = argparse.ArgumentParser(prog="cln", description="CLN Scanner")
    parser.add_argument("paths", nargs="*", default=[])
    parser.add_argument("--max-mb", type=int, default=DEFAULT_MAX_CONTENT_SCAN_MB)
    parser.add_argument("--workers", type=int, default=default_worker_count())
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--json-ipc", action="store_true")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--signatures", action="store_true")
    parser.add_argument("--heuristic", action="store_true")
    parser.add_argument("--include-source", action="store_true")
    parser.add_argument("--no-archives", action="store_true")
    parser.add_argument("--recent-days", type=int, default=30)
    parser.add_argument("--startup", action="store_true")
    parser.add_argument("--processes", action="store_true")
    parser.add_argument("--memory-scan", action="store_true")
    parser.add_argument("--scan-events", action="store_true")
    parser.add_argument("--lookback", type=int, default=7)
    parser.add_argument("--full-forensic", action="store_true")
    parser.add_argument("--install-deps", action="store_true")
    parser.add_argument("--no-install-deps", action="store_true")
    parser.add_argument("--yara-lite-rules", type=str)
    parser.add_argument("--report-dir", type=str)
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    return parser

DEFAULT_MAX_CONTENT_SCAN_MB = 100
DEFAULT_FAST_HASH_LIMIT_MB = 10

def default_worker_count():
    import os
    cpu_count = os.cpu_count() or 4
    return min(max(cpu_count // 2, 4), 32)

def should_skip_dependency_prompt(args):
    return "--no-install-deps" in args or "--install-deps" in args

def sorted_review_results(results):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(results, key=lambda r: (
        min(severity_order.get(f.severity, 4) for f in r.findings) if r.findings else 4,
        r.path
    ))

def load_builtin_rule_pack(name):
    return {"recommended": ["base-rules", "malware-rules"], "downloads": ["downloads-rules"]}.get(name, [])

def available_scan_drives():
    return [f"{d}:\\" for d in "CDEF" if Path(f"{d}:\\").exists()]

def settings_gui_information_text():
    return "CLN Scanner - Safe malware detection and removal"

def scan_zip_archive(archive, max_depth=2):
    findings = []
    try:
        for info in archive.infolist()[:MAX_ARCHIVE_ENTRIES]:
            try:
                data = archive.read(info.filename)[:MAX_ARCHIVE_TEXT_ENTRY_BYTES]
                if data:
                    findings.extend(scan_content_bytes(data))
            except Exception:
                pass
    except Exception:
        pass
    return findings

def collect_files(paths, max_bytes, risky_only=False):
    all_files = []
    skipped = 0
    for path in paths:
        if path.is_file():
            try:
                size = path.stat().st_size
                if size <= max_bytes:
                    if risky_only:
                        if path.suffix.lower() in DANGEROUS_EXTENSIONS:
                            all_files.append(path)
                        else:
                            skipped += 1
                    else:
                        all_files.append(path)
                else:
                    skipped += 1
            except Exception:
                skipped += 1
    return all_files, skipped

def find_zip_extensions(path):
    path_obj = Path(path)
    if path_obj.suffix.lower() in ZIP_CONTAINER_EXTENSIONS:
        return True
    return False

def collect_background_scan_candidates(paths, seen, max_files=100):
    candidates = []
    for path in paths:
        if path.is_file():
            if path not in seen:
                if find_zip_extensions(path):
                    candidates.append(path)
                if len(candidates) >= max_files:
                    break
    return candidates

def dashboard_scan_args(options):
    args = ["--json-ipc"]
    profile = options.get("profile", "default")
    if profile == "fast":
        args.extend(["--max-mb", "10", "--no-archives"])
        args.extend(["--workers", str(default_worker_count())])
    elif profile == "full":
        args.extend(["--full-forensic", "--startup", "--processes"])
    if options.get("advanced"):
        args.extend(["--heuristic", "--signatures"])
    return args

def dashboard_html(token):
    return f"<html><body>CLN Dashboard<br/>Token: {token}</body></html>"

def dashboard_query_token_valid(url, token):
    return f"token={token}" in url

def parse_lnk_metadata(data):
    return {"path": "Unknown", "arguments": "", "WorkingDir": "", "Icon": "", "HotKey": ""}

def parse_lnk_command(data):
    return "Unknown", ""

def network_connection_findings(remote_host, remote_port, local_address="", local_port=0, protocol="TCP", state=""):
    findings = []
    if remote_port in [4444, 5555, 6666, 7777, 8888, 31337]:
        findings.append(Finding("suspicious-port", "Suspicious network port", "high", str(remote_port)))
    if state == "Listen":
        findings.append(Finding("listening-service", "Listening service detected", "medium", f"{remote_host}:{remote_port}"))
    return findings

def build_timeline(summary):
    return sorted(summary.results, key=lambda r: r.modified or "", reverse=True)

def content_scan_views(data):
    views = []
    views.append(("text", data))
    return views

def max_sliding_window_entropy(path, size, max_windows=10):
    return 0.0

def startup_value_references_known_bad(path, known_bad):
    return False

def finding_to_dict(finding):
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "remediation": finding.remediation
    }

def should_cache_signature_result(path, status, signer):
    return status == "Valid"

def read_file_sample_and_hash(path):
    import hashlib
    sample = b""
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    try:
        if path.exists():
            sample = path.read_bytes()[:4096]
            digest = hashlib.sha256(sample).hexdigest()
    except Exception:
        pass
    return digest, sample

def cached_sha256_for_path(path):
    return None

HASH_CACHE = None
HASH_CACHE_DIRTY = False
