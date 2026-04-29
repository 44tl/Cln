# CLN Scanner

CLN is monitored daily, with fast updates for new threats and detection improvements. Join the Discord for instant updates, security notes, and guides: https://discord.gg/cqX6eAmcrp

CLN is a simple, single-file Windows-focused scanner for suspicious downloads, weird new apps, unsigned apps, scam files, scripts, archives, and startup entries.

It is designed to be easy to audit and easy to run:

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

Output JSON:

```powershell
python .\cln.py --json
```

Quarantine confirmed known-bad files:

```powershell
python .\cln.py --clean --startup
```

## What It Checks

- Suspicious executable and script files.
- New runnable files in user folders.
- Unsigned or untrusted Windows apps.
- Fake document names like `invoice.pdf.exe`.
- Scam-like names and script content.
- Zip files containing runnable files.
- Windows startup folder and registry entries.
- Known-bad hashes.

## Safety

CLN reports suspicious signs by default. Cleanup only acts on confirmed known-bad hash matches.

No scanner can catch every threat. Use CLN as one layer alongside Windows Defender, browser protections, and careful account recovery steps after a real infection.
