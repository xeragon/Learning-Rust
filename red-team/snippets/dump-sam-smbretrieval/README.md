# SAM Hive Memory Mapping Loader

Loads the Windows SAM registry hive into a named memory-mapped view for backup and export workflows.

## Usage

Run with administrator or SYSTEM privileges:

```powershell
.\dump-sam-smbretrieval.exe
```

On success, outputs the memory mapping name (e.g., `Global\SAM_Backup_1721759234567`) and keeps the process alive.

## Exit Codes

- **0** — Success; mapping created and name printed to stdout
- **1** — SAM file not found
- **2** — Access denied (insufficient privileges or file locked)
- **4** — Memory mapping creation failed or other Windows API error

## Integration

Intended for use in AD backup scripts. After this program outputs the mapping name, another process can access the SAM hive via:

```rust
use windows_sys::Win32::System::Memory::{OpenFileMapping, MapViewOfFile, FILE_MAP_READ};

let wide_name = /* convert mapping name to wide string */;
let mapping_handle = unsafe { OpenFileMapping(FILE_MAP_READ, false, wide_name.as_ptr()) };
let view = unsafe { MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0) };
// Read from view pointer
```

## Notes

- The SAM hive is typically locked by `lsass.exe` on a running system. This program will fail with exit code 2 unless:
  - Running as SYSTEM with backup privileges
  - Using Volume Shadow Copy (VSS) snapshots
  - Running during maintenance when lsass is not holding the lock
  
- The mapping persists only while this process is running. When it exits, the mapping is closed and no longer accessible.
- Silent operation: only the mapping name or exit code is output.

## Building

```bash
cargo build --release
```

Binary: `target/release/dump-sam-smbretrieval.exe`
