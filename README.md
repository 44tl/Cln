# CLN Scanner

CLN is monitored daily, with fast updates for new threats and detection improvements. Join the Discord for instant updates, security notes, and guides: https://discord.gg/cqX6eAmcrp

CLN is a simple, single-file Windows-focused scanner for suspicious downloads, weird new apps, unsigned apps, scam files, scripts, archives, and startup entries.

It is designed to boot fast, show what it is doing, and avoid expensive work by default. It makes no network calls and does not clean anything unless you ask it to.

The scanner is only `cln.py`. There is no install step and no package to import.

```powershell
python .\cln.py
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

Every scan saves a readable text report:

```text
reports\cln-scan-YYYYMMDD-HHMMSS-microseconds.txt
```

Report, JSON, and terminal output redact common tokens, webhook URLs, control characters, and the current home path by default. Use `--no-redact` only for local forensic work where raw evidence is required.

Deep-check Windows app signatures:

```powershell
python .\cln.py --signatures
```

Scan source-code scripts outside risky folders too:

```powershell
python .\cln.py --include-source
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

## What It Checks

- Suspicious executable and script files.
- New runnable files in user folders.
- Unsigned or untrusted Windows apps when `--signatures` is used.
- File-type mismatches such as renamed executables or disguised shortcuts.
- Fake document names like `invoice.pdf.exe`.
- Scam-like names and script content.
- Zip files, Office documents, Java/Android packages, and browser/package archives containing runnable files.
- Basic visibility for unsupported `.7z`, `.rar`, `.cab`, `.iso`, and `.img` containers.
- Archive path traversal, suspicious compression ratios, embedded macro projects, and external Office links.
- Evidence snippets with byte offsets and line numbers for matched script-content rules.
- Windows startup folders, registry Run entries, Scheduled Tasks, WMI subscriptions, and risky browser extensions.
- Compiled Python artifacts, raw IP indicators, and suspicious URL TLDs in scripts.
- Known-bad hashes.

## Safety

CLN reports suspicious signs by default. Cleanup only acts on built-in confirmed known-bad hash matches unless `--clean-user-hashes` is supplied with `--clean`.

No scanner can catch every threat. Use CLN as one layer alongside Windows Defender, browser protections, and careful account recovery steps after a real infection.
