# CLN Scanner / BETA (EXPECT BUGS)

**Join the Discord for instant updates, security notes, and guides:** https://discord.gg/cqX6eAmcrp

CLN is a simple, single-file Windows-focused scanner for suspicious downloads, weird new apps, unsigned apps, scam files, scripts, archives, and startup entries. It is designed to boot fast, show what it is doing, and avoid expensive work by default. It makes no network calls and does not clean anything unless you ask it to.

---

## Quick Start

```bash
python cln.py
```

Install optional dependencies (YARA support):

```bash
python -m pip install -r requirements.txt
```

---

## Usage

### Basic Scanning

Scan common risk locations (Downloads, Desktop, Documents, temp):

```bash
python cln.py
```

Scan a specific folder:

```bash
python cln.py C:\Users\You\Downloads
```

Scan the whole user profile:

```bash
python cln.py --full
```

### Startup & Process Checks

Include Windows startup checks:

```bash
python cln.py --startup
```

> `--startup` also checks suspicious Scheduled Tasks, WMI event subscriptions, and risky Chromium-family browser extensions when those locations are available.

Include running process checks:

```bash
python cln.py --processes
```

> `--processes` checks command lines for suspicious living-off-the-land usage and, on Windows, scans process memory metadata for executable private regions such as RWX pages.

### Administrator Notes

For the deepest scan, open PowerShell or Command Prompt as Administrator first. Without admin rights, Windows may block locked temp files or protected app files; CLN will skip those and tell you how many were blocked. Temp files can also disappear while the scan is running; CLN counts those as skipped instead of showing them as errors.

### Output Formats

Output JSON:

```bash
python cln.py --json
```

Output CSV for spreadsheet review:

```bash
python cln.py --csv
```

Write SARIF for CI/CD or code scanning:

```bash
python cln.py --sarif .\reports\cln.sarif
```

### Baseline Comparisons

Only show findings that were not present in a previous JSON report:

```bash
python cln.py --json > .\reports\baseline.json
python cln.py --baseline .\reports\baseline.json
```

> Every scan saves a readable text report: `reports\cln-scan-YYYYMMDD-HHMMSS-microseconds.txt`

### GUI Mode

Open the built-in review and removal GUI:

```bash
python cln.py --gui
```

> The GUI shows high and critical findings first, includes finding details and remediation information, and supports quarantining selected file findings. It also includes a full known-bad cleanup action for CLN's built-in `7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab` profile; matching files are hash-verified locally before removal.

### Advanced Options

Deep-check Windows app signatures:

```bash
python cln.py --signatures
```

Scan source-code scripts outside risky folders too:

```bash
python cln.py --include-source
```

Limit nested ZIP recursion for hostile or very complex archives:

```bash
python cln.py --archive-depth 1 C:\Users\You\Downloads
```

Quiet mode:

```bash
python cln.py --quiet
```

### Redaction Control

> Report, JSON, and terminal output redact common tokens, webhook URLs, control characters, and the current home path by default. Use `--no-redact` only for local forensic work where raw evidence is required.

Use a lighter redaction mode when you need to preserve paths but still hide secrets:

```bash
python cln.py --redact-level secrets --json
```

### Cleanup Actions

Quarantine confirmed known-bad files:

```bash
python cln.py --clean --startup
```

> Cleanup acts on built-in confirmed known-bad hashes by default. To also quarantine hashes supplied through `--known-bad`, opt in explicitly:

```bash
python cln.py --known-bad .\hashes.json --clean --clean-user-hashes
```

### Custom Rules & Signatures

Structured hash lists are supported for provenance:

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

Add external content rules without editing `cln.py`:

```bash
python cln.py --rules .\rules.json
```

Run YARA rules when `yara-python` is installed:

```bash
python cln.py --yara-rules .\yara-rules
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
| **GUI Features** | Built-in Tkinter removal GUI with high/critical findings first, selected-file quarantine/delete actions, known-bad hash cleanup |
| **Indicators** | Compiled Python artifacts, raw IP indicators, suspicious URL TLDs in scripts |
| **Hash Lists** | Known-bad hashes and trusted-hash allowlist visibility |

---

## Safety

> CLN reports suspicious signs by default. Cleanup only acts on built-in confirmed known-bad hash matches unless `--clean-user-hashes` is supplied with `--clean`.

No scanner can catch every threat. Use CLN as one layer alongside Windows Defender, browser protections, and careful account recovery steps after a real infection.
