# CLN Scanner / BETA (EXPECT BUGS) - V0.5.0

**Join the Discord for instant updates, security notes, and guides:** https://discord.gg/cqX6eAmcrp

CLN is a simple, single-file Windows-focused scanner for suspicious downloads, weird new apps, unsigned apps, scam files, scripts, archives, and startup entries. It is designed to boot fast, show what it is doing, and avoid expensive work by default. It makes no network calls and does not clean anything unless you ask it to.

---

## Quick Start

**CLI mode (default):**
```bash
python cln.py
```
Scans common risk locations and prints a report to the terminal.

**System tray mode (background + click-to-open GUI):**
```bash
python cln.py --tray
```
Runs a minimal tray icon; click it to open the full settings GUI. Requires `pystray` and `Pillow`:
```bash
python -m pip install -r requirements.txt
```

**GUI mode (scan immediately then show review GUI):**
```bash
python cln.py --gui
```
Performs a scan and opens the graphical review/removal window.

---

## Usage

**Default behavior:** Running `python cln.py` performs a headless scan of common locations (Downloads, Desktop, Documents, temp) and prints a text report. This is CLI-first and works on any platform.

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

### Startup, Process & Behavior Checks

Include Windows startup checks (folders, registry, scheduled tasks, WMI, browser extensions):

```bash
python cln.py --startup
```

Include running process checks (command lines and memory regions):

```bash
python cln.py --processes
```

Analyze process parent-child relationships for Living-off-the-Land patterns:

```bash
python cln.py --behavior
```

Monitor process creations in real-time:

```bash
python cln.py --monitor
```
> `--monitor` is Windows-only and runs until you press `Ctrl+C`.

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

Include a chronological timeline in JSON/text reports:

```bash
python cln.py --timeline
```

### Baseline Comparisons

Only show findings that were not present in a previous JSON report:

```bash
python cln.py --json > .\reports\baseline.json
python cln.py --baseline .\reports\baseline.json
```

> Every scan saves a readable text report: `reports\cln-scan-YYYYMMDD-HHMMSS-microseconds.txt`

### GUI & Tray Modes

Open the built-in review and removal GUI **after** a scan:

```bash
python cln.py --gui
```

> The GUI shows high and critical findings first, includes finding details and remediation information, and supports quarantining selected file findings. It also includes a full known-bad cleanup action for CLN's built-in hashes; matching files are hash-verified locally before removal.

Run CLN as a **system tray application** (Windows only):

```bash
python cln.py --tray
```

> Tray mode starts a small icon in the notification area. Click the icon to open the settings/scan GUI on demand. Combine with `--quiet` to run silently in the background.

### Advanced Options

Deep-check Windows Authenticode signatures:

```bash
python cln.py --signatures
```

Scan source-code scripts outside risky folders too:

```bash
python cln.py --include-source
```

Map local network connections to owning processes (Windows only):

```bash
python cln.py --network
```

Run heuristic entropy and import analysis on PE files:

```bash
python cln.py --heuristic
```

Scan process memory for hollowing and executable regions:

```bash
python cln.py --memory-scan
```

Run self-protection and anti-tampering checks:

```bash
python cln.py --stealth
```

Limit nested ZIP recursion depth:

```bash
python cln.py --archive-depth 4
```

Quiet mode (suppress progress output):

```bash
python cln.py --quiet
```

Disable colored terminal output:

```bash
python cln.py --no-color
```

Run continuous polling scans (multiple rounds):

```bash
python cln.py --continuous --poll-interval 30 --poll-count 3
```

### Scan Profiles

Use a preset profile that bundles common flags:

```bash
python cln.py --profile deep
python cln.py --profile forensic
python cln.py --profile paranoid
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
python cln.py --redact-level secrets --json
```

Disable redaction entirely (local forensic work only):

```bash
python cln.py --no-redact
```

### Cleanup Actions

**Quarantine** confirmed known-bad files (built-in hashes only):

```bash
python cln.py --clean --startup
```

Permanent **delete** instead of quarantine:

```bash
python cln.py --clean --delete
```

Quarantine files matching **user-supplied** hashes (opt-in required):

```bash
python cln.py --known-bad .\hashes.json --clean --clean-user-hashes
```

> Cleanup acts on built-in known-bad hashes by default. To also act on `--known-bad` hashes, you must supply `--clean-user-hashes`. Files are moved to the `quarantine/` folder and a manifest is written so they can be restored.

Restore a quarantined file from a manifest:

```bash
python cln.py --restore .\quarantine\manifest.json
```

### Custom Rules & Signatures

Add external content rules without editing `cln.py`:

```bash
python cln.py --rules .\rules.json
```

Run YARA rules when `yara-python` is installed:

```bash
python cln.py --yara-rules .\yara-rules
```

Run CLN's built-in YARA-lite rule engine:

```bash
python cln.py --yara-lite-rules rules\cln-strong.yara-lite.json
```

Provide your own known-bad and known-good hash lists:

```bash
python cln.py --known-bad .\bad-hashes.json --known-good .\good-hashes.json
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
python cln.py --report-dir .\reports
```

Change the quarantine directory:

```bash
python cln.py --quarantine-dir .\quarantine
```

Export an evidence bundle (copies high-risk samples + metadata):

```bash
python cln.py --bundle .\evidence
```

Limit content scan size (default 75 MB):

```bash
python cln.py --max-mb 150
```

Adjust parallel worker count (default: auto):

```bash
python cln.py --workers 8
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
