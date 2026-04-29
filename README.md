# CLN Scanner

CLN is monitored daily, with fast updates for new threats and detection improvements. Join the Discord for instant updates, security notes, and guides: https://discord.gg/cqX6eAmcrp

CLN is a simple, single-file Windows-focused scanner for suspicious downloads, weird new apps, unsigned apps, scam files, scripts, archives, and startup entries.

It is designed to boot fast, show what it is doing, and avoid expensive work by default. It makes no network calls and does not clean anything unless you ask it to.

The scanner is only `cln.py`. There is no install step for the default scanner and no package to import.

### Project Demo
<video src="demo.mp4" controls="controls" style="max-width: 100%;">
  Your browser does not support the video tag.
</video>

```powershell
python .\cln.py
```

Optional integrations such as YARA support are listed in `requirements.txt`:

```powershell
python -m pip install -r requirements.txt
```

## Run

Scan common risk locations such as Downloads, Desktop, Documents, and temp:

```powershell
python .\cln.py
```

Scan a specific folder:

```powershell
python .\cln.py C:\Users\You\Downloads
```

Scan the whole user profile:

```powershell
python .\cln.py --full
```

Include Windows startup checks:

```powershell
python .\cln.py --startup
```

`--startup` also checks suspicious Scheduled Tasks, WMI event subscriptions, and risky Chromium-family browser extensions when those locations are available.

For the deepest scan, open PowerShell or Command Prompt as Administrator first. Without admin rights, Windows may block locked temp files or protected app files; CLN will skip those and tell you how many were blocked. Temp files can also disappear while the scan is running; CLN counts those as skipped instead of showing them as errors.

Output JSON:

```powershell
python .\cln.py --json
```

Output CSV for spreadsheet review:

```powershell
python .\cln.py --csv
```

Write SARIF for CI/CD or code scanning:

```powershell
python .\cln.py --sarif .\reports\cln.sarif
```

Only show findings that were not present in a previous JSON report:

```powershell
python .\cln.py --json > .\reports\baseline.json
python .\cln.py --baseline .\reports\baseline.json
```

Every scan saves a readable text report:

```text
reports\cln-scan-YYYYMMDD-HHMMSS-microseconds.txt
```

Report, JSON, and terminal output redact common tokens, webhook URLs, control characters, and the current home path by default. Use `--no-redact` only for local forensic work where raw evidence is required.

Use a lighter redaction mode when you need to preserve paths but still hide secrets:

```powershell
python .\cln.py --redact-level secrets --json
```

Deep-check Windows app signatures:

```powershell
python .\cln.py --signatures
```

Scan source-code scripts outside risky folders too:

```powershell
python .\cln.py --include-source
```

Limit nested ZIP recursion for hostile or very complex archives:

```powershell
python .\cln.py --archive-depth 1 C:\Users\You\Downloads
```

Quiet mode:

```powershell
python .\cln.py --quiet
```

Quarantine confirmed known-bad files:

```powershell
python .\cln.py --clean --startup
```

Cleanup acts on built-in confirmed known-bad hashes by default. To also quarantine hashes supplied through `--known-bad`, opt in explicitly:

```powershell
python .\cln.py --known-bad .\hashes.json --clean --clean-user-hashes
```

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

```powershell
python .\cln.py --rules .\rules.json
```

Run YARA rules when `yara-python` is installed:

```powershell
python .\cln.py --yara-rules .\yara-rules
```

## What It Checks

- Suspicious executable and script files.
- New runnable files in user folders.
- Unsigned or untrusted Windows apps when `--signatures` is used.
- File-type mismatches such as renamed executables or disguised shortcuts.
- Fake document names like `invoice.pdf.exe`.
- Scam-like names and script content.
- Zip files, Office documents, Java/Android packages, and browser/package archives containing runnable files.
- Basic visibility for unsupported `.7z`, `.rar`, `.cab`, `.iso`, and `.img` containers.
- Archive path traversal, suspicious compression ratios, nested ZIPs, embedded macro projects, and external Office links.
- Configurable nested ZIP recursion depth, with depth-limit findings for skipped inner archives.
- Sliding-window entropy checks for risky executables and scripts.
- PE header checks for writable executable sections and unusual entry points.
- Basic PDF JavaScript/Launch indicators, legacy Office macro indicators, and suspicious shortcut targets.
- Evidence snippets with byte offsets and line numbers for matched script-content rules.
- Windows startup folders, registry Run/RunOnce entries, IFEO debugger keys, shell icon overlay handlers, Scheduled Tasks, WMI subscriptions, and risky browser extensions.
- Compiled Python artifacts, raw IP indicators, and suspicious URL TLDs in scripts.
- Known-bad hashes and trusted-hash allowlist visibility.

## Safety

CLN reports suspicious signs by default. Cleanup only acts on built-in confirmed known-bad hash matches unless `--clean-user-hashes` is supplied with `--clean`.

No scanner can catch every threat. Use CLN as one layer alongside Windows Defender, browser protections, and careful account recovery steps after a real infection.
