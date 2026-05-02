# Watchdog Monitoring Architecture

## Overview
The legacy polling loop in `run_continuous_scan` has been replaced with an event-driven file system monitoring architecture using the `watchdog` library.

## Benefits
- **Zero Idle CPU**: No background threads are repeatedly walking the disk while idle.
- **Instant Response**: Scans are triggered immediately upon file `creation` or `modification` events.
- **Low I/O Overhead**: Only the specific changed files are scanned, rather than re-indexing entire directories.

## Architecture
- **Event Handler (`ScannerEventHandler`)**: Captures OS-level events, ensuring directories are ignored and actual file modifications trigger the scan.
- **Observer**: Manages the native OS file system hooks (`ReadDirectoryChangesW` on Windows).
- **Deduplication**: A `seen` set avoids duplicate entries if a single action triggers multiple OS-level events.
