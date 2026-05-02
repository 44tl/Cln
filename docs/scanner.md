# CLN Scanner Module Documentation

## Overview

The CLN Scanner module (`cln_scanner.py`) is the core scanning engine that handles all file and system analysis tasks. It examines files for suspicious patterns, analyzes documents, checks archives, and inspects system components like startup items and running processes.

## What the Scanner Does

The scanner looks for warning signs in your files and system. It checks for suspicious file types, dangerous extensions, renamed executables, embedded threats in archives, and unusual patterns that might indicate malware. The scanner does not delete anything by default. It only reports what it finds so you can decide what to do.

## Key Features

### File Analysis

The scanner examines individual files to detect potential threats. It checks file headers to identify the actual file type, even when the extension has been changed to hide the true nature of the file. It calculates cryptographic hashes to identify known bad files and compare against known good allowlists. The scanner also measures file entropy to detect packed or obfuscated executables that might be hiding malicious code.

### Archive Inspection

CLN can look inside ZIP files, Office documents, Java archives, and Android packages. It examines file names inside archives for suspicious patterns like executable files disguised as documents. The scanner checks for path traversal attempts and unusual compression ratios that might indicate malicious content.

### Document Analysis

The scanner examines PDF files for embedded JavaScript, automatic actions that run when you open the document, and external links. It checks Office documents for macros and embedded objects that could contain malicious code. It also inspects shortcut files to see what programs they actually launch.

### Startup Item Scanning

On Windows, the scanner checks locations where malware often hides to run automatically. This includes startup folders, registry Run keys, scheduled tasks, and browser extensions. These locations are common persistence mechanisms used by both legitimate software and malware.

### Process Inspection

The scanner can examine running processes on your system. It checks process command lines for suspicious patterns and can map active network connections to the processes that created them. This helps identify malware that is currently running on your system.

## Using the Scanner

### Basic Scan

To scan common locations like Downloads, Desktop, and Documents folders:

```bash
python cln.py --cli
```

This runs a quick scan and prints results to your terminal.

### Scan Specific Locations

To scan a specific folder:

```bash
python cln.py C:\Users\YourName\Downloads
```

### Full Profile Scan

To scan your entire user profile including all subfolders:

```bash
python cln.py --full
```

### Deep Scan

For more thorough scanning with signature verification:

```bash
python cln.py --profile deep
```

### Startup Items Check

To include startup location scanning:

```bash
python cln.py --startup
```

### Process Inspection

To check running processes:

```bash
python cln.py --processes
```

## Scan Profiles

CLN provides different scan profiles that bundle common settings together. Choose the profile that fits your needs.

| Profile | Description |
|---------|-------------|
| fast | Quick scan of common risky locations. Good for everyday use. |
| deep | Adds stronger file analysis, archive inspection, and signature checks. |
| forensic | Includes startup items, processes, network connections, and timeline output. |
| paranoid | Raises all limits for maximum coverage, may take longer. |

## Output Formats

### Text Report (Default)

Results print directly to your terminal with color coding:

```bash
python cln.py --cli
```

### JSON Output

For integration with other tools:

```bash
python cln.py --json
```

### CSV Output

For spreadsheet review:

```bash
python cln.py --csv
```

### SARIF Output

For CI/CD integration:

```bash
python cln.py --sarif .\reports\cln.sarif
```

## Understanding Results

### Verdict Levels

The scanner assigns verdicts based on what it finds:

* **dangerous** - High priority findings that likely indicate active malware
* **suspicious** - Warning signs that deserve attention
* **review** - Items to examine further
* **clean** - No suspicious indicators found
* **error** - Could not complete analysis

### Finding Details

Each finding includes:

* A title describing what was found
* A severity level (critical, high, medium, low, info)
* Details about the specific indicator
* Recommended next steps

## Configuration Options

### Content Size Limit

Control how much of each file gets analyzed:

```bash
python cln.py --max-mb 150
```

### Worker Threads

Adjust parallel scanning speed:

```bash
python cln.py --workers 8
```

### Archive Depth

Control how deep nested archives get inspected:

```bash
python cln.py --archive-depth 4
```

### Recent File Age

Define what counts as a new file:

```bash
python cln.py --recent-days 30
```

## Custom Rules

### Hash Allowlists

Provide known good hashes to skip:

```bash
python cln.py --known-good .\good-hashes.json
```

### Custom Content Rules

Add your own detection rules:

```bash
python cln.py --rules .\my-rules.json
```

### YARA Rules

Use YARA signature files:

```bash
python cln.py --yara-rules .\malware.yar
```

### Built-in YARA-lite

Use CLN's included rule engine:

```bash
python cln.py --yara-lite-rules rules\cln-strong.yara-lite.json
```

## Continuous Monitoring

Run multiple scan rounds to catch intermittent threats:

```bash
python cln.py --continuous --poll-interval 30 --poll-count 3
```

## Troubleshooting

### Scanner Won't Start

Make sure you have the required dependencies:

```bash
python -m pip install -r requirements.txt
```

### Permission Errors

Some scans require administrator privileges. Run your terminal as Administrator for full access.

### Performance Issues

Reduce worker count for slower systems:

```bash
python cln.py --workers 4
```

### Archive Scanning Slow

Disable archive inspection for faster scans:

```bash
python cln.py --no-archives
```

## File Type Detection

CLN can identify these file types regardless of extension:

| Type | Indicators |
|------|------------|
| Executable | PE/COFF header (MZ) |
| PDF | %PDF magic bytes |
| ZIP | PK\x03\x04 signature |
| Office | OLE compound document |
| ELF | Linux executable |

## Security Notes

The scanner is designed to be safe and non-destructive. It never modifies files, never sends data to external servers, and never deletes anything without explicit permission. All cleanup actions require you to use the --clean flag and confirm each action.

For more information about the antivirus module, see [AV Module Documentation](av.md).

---

[Back to Main README](../README.md)
