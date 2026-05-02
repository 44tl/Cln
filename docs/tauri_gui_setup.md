# CLN Tauri GUI Setup & Build Instructions

## Overview
The CLN Scanner features a modern, high-performance Graphical User Interface (GUI) built with Tauri 2.0. The architecture uses a Rust backend to securely spawn the core Python scanning logic (`cln_scanner.py` and `cln_av.py`) via local inter-process communication (IPC). 

## Prerequisites (Windows)
1. **Node.js (v18+)**: Required for building the React frontend.
2. **Rust Toolchain (`rustup`)**: Required for compiling the Tauri backend.
3. **C++ Build Tools**: Install via Visual Studio Build Tools.

## Development Setup
```cmd
cd cln-gui
npm install
npm run tauri dev
```

## Production Build
To compile a highly optimized, standalone executable:
```cmd
cd cln-gui
npm run tauri build
```
The output installers will be located in: `cln-gui/src-tauri/target/release/bundle/`.

## Architecture & Security
- **JSON IPC Mode**: When the Rust backend spawns the Python scripts, it appends the `--json-ipc` flag to stream strongly-typed JSON schemas back to the React UI.
- **Rule 10 Compliance**: The Tauri interface does not contain any inherent scanning intelligence, keeping logic seated in the mandated Python core.
