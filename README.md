# CLN Scanner / v0.6.0 BETA (EXPECT BUGS)

**Join the Discord for instant updates, security notes, and guides:** https://discord.gg/cqX6eAmcrp

CLN is a lightweight, Windows-focused forensic scanner and antivirus designed to detect suspicious downloads, unsigned applications, scam scripts, and persistence mechanisms. Version 0.6.0 introduces a high-performance Tauri 2.0 GUI, AES-256 encrypted quarantine, and native OS interrogation bypassing all shell-based subprocesses.

> [!NOTE]
> CLN Anti-Virus won't be published before any full testing, proper production test, and polishing. But scanner is out and it doesn't require full test.

---

## Documentation Guide

This documentation covers four main areas:

| Section | Description |
|---------|-------------|
| [Tauri GUI Setup](docs/tauri_gui_setup.md) | **[NEW]** Instructions for building and running the modern desktop dashboard. |
| [Quarantine Security](docs/quarantine_monitoring.md) | **[NEW]** Technical details on the AES-256-CBC encrypted keystore. |
| [Watchdog Monitoring](docs/watchdog_monitoring.md) | **[NEW]** Real-time event-driven file system monitoring. |
| [Forensic Scans](docs/scanner.md) | Deep analysis for WMI, Registry, and Process memory anomalies. |

---

## Quick Start

**Native Tauri GUI (Recommended):**
```bash
python cln_scanner.py --gui
```
Opens the modern desktop dashboard. Requires initial compilation via `npm run tauri build`.

**System Tray Mode:**
```bash
python cln_av.py
```
Starts a background tray icon. Access the GUI, Quarantine, or Settings via the context menu.

**Headless Fast Scan:**
```bash
python cln_scanner.py
```
Performs a rapid scan of common risk locations (Downloads, Desktop, Documents, Temp) and prints findings to the terminal.

---

## Module Structure

CLN consists of these main components:

| File | Purpose |
|------|---------|
| `cln_scanner.py` | Main entry point & scanning engine for file analysis |
| `cln_av.py` | Antivirus operations, background tray, and utilities |
| `cln_modules/` | Forensic, quarantine, and detection modules |

The CLN architecture separates the scanning engine from the antivirus management. You typically run `cln_scanner.py` for direct system analysis or `cln_av.py` for background protection.

---

## Usage

**Default behavior:** Running `python cln_av.py` starts CLN in system tray mode. A notification balloon appears: "CLN is now running, open/close CLN from your tray." Click the tray icon to open the scanner GUI, access Settings, or Quit. This is the recommended mode for interactive use. To perform an immediate headless scan, use `--cli` (see below).

### Basic Scanning

Scan common risk locations (Downloads, Desktop, Documents, temp) in headless mode:

```bash
python cln_scanner.py --cli
```

Scan a specific folder (path provided automatically triggers a scan):

```bash
python cln_scanner.py C:\Users\You\Downloads
```

Scan the whole user profile:

```bash
python cln_scanner.py --full
```

### Startup, Process & Behavior Checks

Include Windows startup checks (folders, registry, scheduled tasks, WMI, browser extensions):

```bash
python cln_scanner.py --startup
```

Include running process checks (command lines and memory regions):

```bash
python cln_scanner.py --processes
```

Analyze process parent-child relationships for Living-off-the-Land patterns:

```bash
python cln_scanner.py --behavior
```

Monitor process creations in real-time:

```bash
python cln_scanner.py --monitor
```
> `--monitor` is Windows-only and runs until you press `Ctrl+C`.

### Administrator Notes

For the deepest scan, open PowerShell or Command Prompt as Administrator first. Without admin rights, Windows may block locked temp files or protected app files; CLN will skip those and tell you how many were blocked. Temp files can also disappear while the scan is running; CLN counts those as skipped instead of showing them as errors.

### Output Formats

Output JSON:

```bash
python cln_scanner.py --json
```

Output CSV for spreadsheet review:

```bash
python cln_scanner.py --csv
```

Write SARIF for CI/CD or code scanning:

```bash
python cln_scanner.py --sarif .\reports\cln.sarif
```

Include a chronological timeline in JSON/text reports:

```bash
python cln_scanner.py --timeline
```

### Baseline Comparisons

Only show findings that were not present in a previous JSON report:

```bash
python cln_scanner.py --json > .\reports\baseline.json
python cln_scanner.py --baseline .\reports\baseline.json
```

> Every scan saves a readable text report: `reports\cln-scan-YYYYMMDD-HHMMSS-microseconds.txt`

### GUI & Tray Modes

Open the modern Tauri 2.0 GUI interface **before or after** a scan to manage settings, review findings, and run scans from an interactive dashboard:

```bash
python cln_scanner.py --gui
```

or

```bash
python cln_av.py --gui
```

> **Note:** The GUI is a native Rust/React application built with Tauri. You must compile the application first before the `--gui` flag will work. Please see [Tauri GUI Setup & Build Instructions](docs/tauri_gui_setup.md) for full compilation details.

**System Tray Mode (default for AV):**

Running `python cln_av.py` with no arguments starts CLN in system tray mode. A notification balloon appears: "CLN is now running, open/close CLN from your tray."

The tray icon provides the following context menu:

- **Open Scanner** - Opens the Tauri GUI for scanning
- **Settings** - Opens the settings/configuration GUI
- **Quit** - Exits the application

You can also double-click the tray icon to open the main scanner GUI.

> The tray runs silently in the background. The main GUI window only appears when explicitly requested through the tray menu or by double-clicking the tray icon.

### Forensic Scans

CLN provides comprehensive forensic capabilities to detect advanced persistence mechanisms and in-memory anomalies. These scans require Administrator privileges to function correctly.

Run all forensic checks, including memory forensics, process memory inspection, WMI, and deep registry checks:

```bash
python cln_scanner.py --full-forensic
```

**Interpreting Forensic Output:**
- **Registry Persistence (`registry-persistence`):** Flags unknown executables in Run/RunOnce keys. A finding indicates a program configured to start automatically that is not in the system whitelist.
- **WMI Event Consumers (`wmi-consumer`):** Flags suspicious WMI consumers, missing target executables, or unsigned scripts used for fileless persistence.
- **Process Memory Regions (`memory-region`):** Detects injected code (e.g., Cobalt Strike beacons or hollowed processes) by scanning for RWX (Read-Write-Execute) memory pages with high entropy (> 7.2).
- **Memory Forensics (`memory-forensics`):** Attempts to acquire a live kernel memory dump using WinPMEM and analyze it using Volatility3 plugins (pslist, malfind, netscan, callbacks) to discover hidden processes, hooked SSDT entries, and malicious network sockets. Output is provided as a consolidated JSON summary.

### Advanced Options

Deep-check Windows Authenticode signatures:

```bash
python cln_scanner.py --signatures
```

Scan source-code scripts outside risky folders too:

```bash
python cln_scanner.py --include-source
```

Map local network connections to owning processes (Windows only):

```bash
python cln_scanner.py --network
```

Run heuristic entropy and import analysis on PE files:

```bash
python cln_scanner.py --heuristic
```

Scan process memory for hollowing and executable regions:

```bash
python cln_scanner.py --memory-scan
```

Run self-protection and anti-tampering checks:

```bash
python cln_scanner.py --stealth
```

Limit nested ZIP recursion depth:

```bash
python cln_scanner.py --archive-depth 4
```

Quiet mode (suppress progress output):

```bash
python cln_scanner.py --quiet
```

Disable colored terminal output:

```bash
python cln_scanner.py --no-color
```

Run continuous polling scans (multiple rounds):

```bash
python cln_scanner.py --continuous --poll-interval 30 --poll-count 3
```

> Continuous scans now use file hash tracking. After the first round, only new or changed files (different SHA-256) are reported in subsequent rounds. A `continuous-scan-complete` finding marks when all polling rounds finish.

### Scan Profiles

Use a preset profile that bundles common flags:

```bash
python cln_scanner.py --profile deep
python cln_scanner.py --profile forensic
python cln_scanner.py --profile paranoid
```

| Profile | Purpose |
|---------|---------|
| `fast` | Quick local checks for common risky locations. |
| `deep` | Adds stronger file, archive, signature, and source coverage. |
| `forensic` | Adds startup, process, network, and timeline checks. |
| `paranoid` | Raises scan limits and depth for maximum review. |

### Redaction Control

Report, JSON, and terminal output redact common tokens, webhook URLs, control characters, and the current home path by default.

Use a lighter redaction mode when you need to preserve paths but still hide secrets:

```bash
python cln_scanner.py --redact-level secrets --json
```

Disable redaction entirely (local forensic work only):

```bash
python cln_scanner.py --no-redact
```

### Cleanup Actions

**Quarantine** confirmed known-bad files (built-in hashes only):

```bash
python cln_scanner.py --clean --startup
```

Permanent **delete** instead of quarantine:

```bash
python cln_scanner.py --clean --delete
```

Quarantine files matching **user-supplied** hashes (opt-in required):

```bash
python cln_scanner.py --known-bad .\hashes.json --clean --clean-user-hashes
```

> Cleanup acts on built-in known-bad hashes by default. To also act on `--known-bad` hashes, you must supply `--clean-user-hashes`. Files are moved to the `quarantine/` folder and a manifest is written so they can be restored.

Restore a quarantined file from a manifest:

```bash
python cln_scanner.py --restore .\quarantine\manifest.json
```

### Custom Rules & Signatures

Add external content rules without editing `cln.py`:

```bash
python cln_scanner.py --rules .\rules.json
```

Run YARA rules when `yara-python` is installed:

```bash
python cln_scanner.py --yara-rules .\yara-rules
```

Run CLN's built-in YARA-lite rule engine:

```bash
python cln_scanner.py --yara-lite-rules rules\cln-strong.yara-lite.json
```

The YARA-lite engine is a complete custom implementation (lexer, parser, evaluator) that supports a comprehensive subset of YARA syntax without requiring the `yara-python` package. Features include:

- **Pattern modifiers:** `nocase`, `fullword`, `wide`, `ascii`, `regex`, `base64`, `xor<key>`
- **Condition evaluation:** Boolean logic (`and`, `or`, `not`), arithmetic (`+ - * / % >> <<`), comparisons (`== != > >= < <=`), string membership (`in`, `contains`)
- **Built-in functions:** `filesize`, `entropy`, `uint8(offset)`, `uint16(offset)`, `uint32(offset)`, `int8`, `int16`, `int32`, plus PE helpers (`peimagebase`, `peentrypoint`, `ispe`, `isdll`, `isexec`, `is64bit`)
- **Security:** No use of `eval()` or `exec()`; all expressions are parsed and interpreted safely.
- **Performance:** Compiled patterns are cached per rule for efficient scanning.

See `rules/cln-strong.yara-lite.json` for example rule syntax.

Provide your own known-bad and known-good hash lists:

```bash
python cln_scanner.py --known-bad .\bad-hashes.json --known-good .\good-hashes.json
```

Structured hash lists with provenance metadata:

```json
{
  "schema": "cln-hash-list-v1",
  "description": "Internal confirmed bad hashes",
  "updated_at": "2026-04-30T00:00:00Z",
  "hashes": [
    {"sha256": "7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab", "description": "known bad sample"}
  ]
}
```

Change the report output directory:

```bash
python cln_scanner.py --report-dir .\reports
```

Change the quarantine directory:

```bash
python cln_scanner.py --quarantine-dir .\quarantine
```

Export an evidence bundle (copies high-risk samples + metadata):

```bash
python cln_scanner.py --bundle .\evidence
```

Limit content scan size (default 75 MB):

```bash
python cln_scanner.py --max-mb 150
```

Adjust parallel worker count (default: auto):

```bash
python cln_scanner.py --workers 8
```

### Advanced Features

**Incremental Scanning with Manifests:**
Track file states and only scan changed files for significantly faster rescans.
```bash
python cln_scanner.py --manifest baseline.json --continuous
```
The manifest stores hashes, timestamps, and previous scan results.

**Structured Error Telemetry:**
Capture detailed scanning failures including error types, stack traces, and line numbers for better troubleshooting. Errors are automatically included in JSON reports.

**Enhanced Continuous Monitoring:**
Poll for changes at intervals and only perform delta scans.
```bash
python cln_scanner.py --continuous --poll-interval 60 --poll-count 10 --manifest baseline.json
```

**True YARA Support:**
Use official YARA rules for robust malware detection.
```bash
python cln_scanner.py --yara-rules rules/malware.yar
```

---

## What It Checks

| Category | Description |
|----------|-------------|
| **Executable & Scripts** | Suspicious executable and script files, new runnable files in user folders |
| **Signatures** | Unsigned or untrusted Windows apps when `--signatures` is used |
| **File Type Mismatches** | Renamed executables, disguised shortcuts |
| **Fake Documents** | Names like `invoice.pdf.exe`, scam-like names |
| **Archives** | ZIP, Office documents, Java/Android packages, browser/package archives |
| **Archive Analysis** | Archive path traversal, suspicious compression ratios, nested ZIPs, embedded macro projects, external Office links |
| **Entropy Checks** | Sliding-window entropy checks for risky executables and scripts |
| **PE Analysis** | ImpHash, suspicious section names, high-entropy executable sections, writable executable sections, risky import clusters, timestamp anomalies, unusual entry points |
| **Shortcut Parsing** | Native LNK string parsing for shortcut targets and arguments |
| **PDF Analysis** | JavaScript, open/launch actions, additional actions, embedded files |
| **OLE Extraction** | Legacy OLE string extraction for VBA auto-start, shell execution, obfuscation indicators |
| **Script Deobfuscation** | Lightweight script string resolution for simple concatenation, reversal, replace, and character-array obfuscation before content rules run |
| **Evidence Snippets** | Byte offsets and line numbers for matched script-content rules |
| **Startup Locations** | Windows startup folders, registry Run/RunOnce entries, current-user COM overrides, IFEO debugger keys, AppInit/AppCert DLL settings, shell icon overlay handlers, Scheduled Tasks, WMI subscriptions, risky browser extensions |
| **Process Checks** | Optional running process command-line and executable private memory checks with `--processes` |
| **Behavior Graph** | Parent-child process lineage analysis with `--behavior` |
| **Real-time Monitor** | Process-creation monitoring with `--monitor` |
| **Network-Local** | Active TCP/UDP connections mapped to processes with `--network` |
| **GUI Features** | Built-in Tkinter removal GUI with high/critical findings first, selected-file quarantine/delete actions, known-bad hash cleanup |
| **Indicators** | Compiled Python artifacts, raw IP indicators, suspicious URL TLDs in scripts |
| **Hash Lists** | Known-bad hashes and trusted-hash allowlist visibility |

---

## Safety

> CLN reports suspicious signs by default. Cleanup only acts on built-in confirmed known-bad hash matches unless `--clean-user-hashes` is supplied with `--clean`. Files are moved to a quarantine folder, not deleted, and a manifest is written so they can be restored.

No scanner can catch every threat. Use CLN as one layer alongside Windows Defender, browser protections, and careful account recovery steps after a real infection.
