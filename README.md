# DLL Injector

## Features

- Process Manager with search and quick attach
- Memory Viewer (placeholder)
- DLL Injector with progress and logging
- Disassembly view (placeholder)
- Keyauth Patcher tab (safe): key entry, simulated validation, safe detection placeholder

## Requirements

See `requirements.txt`.

## Usage

1. Run the application:

```bash
python3 dll_injector.py
```

2. Attach to a running process from the Process Manager tab.
3. Use the DLL Injector tab to select and inject a DLL (Windows only).
4. Use the Disassembly tab for a basic disassembly preview (placeholder).
5. Use the Keyauth Patcher tab to:
   - Enter a license key and run a simulated validation (no network).
   - Optionally enable auto-detect to run a safe placeholder detection after attach.

Notes:
- The Keyauth Patcher tab does not bypass, patch, or alter any protection. It is a UI placeholder to manage keys and demonstrate detection wiring without impacting the target process.

## Development

- PyQt5 UI
- Uses `psutil` for process enumeration
