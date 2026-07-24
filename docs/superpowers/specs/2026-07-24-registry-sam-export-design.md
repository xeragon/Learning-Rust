# Registry-Based SAM Hives Export Tool — Design Spec

**Date:** 2026-07-24  
**Project:** registry-dump-smb  
**Scope:** Export Windows SAM, SYSTEM, and SECURITY registry hives to SMB share using Registry APIs

---

## Overview

A standalone Windows tool that queries the Windows registry directly (avoiding lsass.exe locking) to read SAM, SYSTEM, and SECURITY hives, reconstructs them in binary registry hive format, and transfers them to an SMB backup share. Designed as a replacement for the file-based hive loader, using Registry APIs instead of file I/O.

**Target environment:** Windows domain controller (or any system with administrator privileges)

---

## Requirements

### Functional
1. Read SAM, SYSTEM, and SECURITY registry hives using Windows Registry APIs (RegOpenKeyEx, RegEnumKeyEx, RegQueryValueEx)
2. Recursively enumerate all registry keys and values within each hive
3. Reconstruct registry hives in binary hive file format (native Windows format)
4. Export to SMB share as three files: `SAM.bin`, `SYSTEM.bin`, `SECURITY.bin`
5. Support SMB authentication via optional command-line parameters
6. Accept SMB path and credentials (username, password) as optional parameters

### Non-Functional
- **Silent operation:** No console output except exit codes; no error messages
- **Error handling:** Exit with specific codes (0-6) based on failure type
- **No file I/O:** Use Registry APIs only; no temporary files or disk writes
- **In-memory processing:** Build binary hives entirely in memory before SMB write
- **No privilege escalation:** Assume administrator/SYSTEM privileges already present
- **Sequential export:** Export hives one at a time, fail-fast on first error

---

## Architecture

### Single Responsibility
One executable with one function: read three registry hives via API → reconstruct binary format → export to SMB

### Components

**1. Registry Reader**
- Input: Registry path (HKLM\SAM, HKLM\SYSTEM, HKLM\SECURITY)
- Process: Open registry key, recursively enumerate subkeys and values
- Output: In-memory registry data structure
- Responsible for: Registry API calls, data traversal, error mapping for registry failures

**2. Hive Builder**
- Input: In-memory registry data structure
- Process: Reconstruct binary registry hive format (header + key records + value records)
- Output: Binary hive bytes ready for file write
- Responsible for: Binary format reconstruction, checksum calculation, offset management

**3. SMB Writer**
- Input: Binary hive data, SMB path, filename, credentials
- Process: Connect to SMB, create/overwrite file, write binary data
- Output: Success or error code
- Responsible for: SMB connection, file creation, authentication, I/O errors

**4. CLI Parser**
- Input: Command-line arguments
- Process: Parse optional flags (--path, --username, --password)
- Output: Validated parameters or exit code 6 (invalid args)
- Responsible for: Argument parsing, default value handling

**5. Error Handler**
- Input: Windows/network error codes
- Process: Map to application exit codes (0-6)
- Output: Exit code
- Responsible for: Error code mapping, silent operation

### Data Flow

```
CLI: registry-dump-smb.exe [--path <smb_path>] [--username <user>] [--password <pass>]
    ↓
1. Parse arguments (--path, --username, --password all optional)
    ↓
2. Connect to SMB share (if --path provided)
    ↓
3. For each hive (SAM → SYSTEM → SECURITY):
    a. Open registry key via RegOpenKeyEx
    b. Recursively read keys/values via RegEnumKeyEx/RegQueryValueEx
    c. Build binary hive format in memory
    d. Write to SMB as SAM.bin, SYSTEM.bin, SECURITY.bin
    ↓
Exit 0 (success) or error code (silent)
```

---

## Technical Details

### Registry API Calls
1. **RegOpenKeyEx** — Open registry key handle (HKLM\SAM, HKLM\SYSTEM, HKLM\SECURITY)
2. **RegEnumKeyEx** — Enumerate subkeys recursively
3. **RegQueryValueEx** — Read value data and type
4. **RegCloseKey** — Close key handles
5. **GetLastError** — Retrieve Windows error codes

### Binary Hive Format

Registry hives follow a specific binary format:

**File Header (4 KB)**
- Magic bytes: "regf" (0x72656766)
- Version information (hive format version)
- Timestamp (when hive was written)
- Checksum of header
- Root key offset
- Hive length

**Key Records (nk records)**
- Key name and length
- Subkey count and offset pointers
- Value count and offset pointers
- Security descriptor offset
- Timestamps (LastWriteTime)

**Value Records (vk records)**
- Value name and length
- Value type (REG_SZ, REG_DWORD, etc.)
- Value data size and offset
- Data storage location

**Data Cells**
- Raw value data storage
- String/binary data blobs

The tool reconstructs this format exactly as it appears in the live registry, creating a binary-identical export suitable for import via `reg.exe import`.

### Error Handling & Exit Codes

| Exit | Meaning | Scenario |
|------|---------|----------|
| 0 | Success | All three hives exported to SMB |
| 1 | Registry key not found | SAM/SYSTEM/SECURITY not accessible |
| 2 | Access denied | Insufficient privilege to read registry |
| 3 | SMB auth failed | Username/password incorrect |
| 4 | SMB path not found | Share unreachable or doesn't exist |
| 5 | SMB write failed | Disk space, permissions, or I/O error |
| 6 | Other errors | Memory, format reconstruction, unexpected failures |

**Behavior:**
- Fail-fast: Exit at first error, do not attempt remaining hives
- Silent: No output except exit code
- No retry: Caller implements retry logic if needed

### SMB Connection

- Establish connection via `WNetAddConnectionW` with optional credentials
- Write binary files using `CreateFileW` and `WriteFile` (SMB paths treated as local paths)
- Overwrite existing files without prompting
- Close connection on completion or error

### Command-Line Parameters

```
registry-dump-smb.exe [--path <smb_path>] [--username <user>] [--password <pass>]
```

**Parameters (all optional):**
- `--path <smb_path>` — UNC path to SMB backup directory (default: current user's default backup location or fail if not set)
- `--username <user>` — SMB authentication username (default: current user credentials)
- `--password <pass>` — SMB authentication password (default: current user credentials)

**Examples:**
```powershell
registry-dump-smb.exe --path \\backup-server\hives --username domain\admin --password P@ss
registry-dump-smb.exe --path \\nas\backups\dc01
registry-dump-smb.exe  # Uses defaults
```

---

## Success Criteria

1. ✓ Program accepts optional command-line parameters (--path, --username, --password)
2. ✓ Reads SAM, SYSTEM, SECURITY registry hives via Registry APIs (no file I/O)
3. ✓ Recursively enumerates all registry keys and values
4. ✓ Reconstructs binary registry hive format in memory
5. ✓ Exports to SMB as three files (SAM.bin, SYSTEM.bin, SECURITY.bin)
6. ✓ Exits with correct error codes (0-6)
7. ✓ Silent operation: no output except exit code
8. ✓ Sequential export: fail-fast on first error
9. ✓ No temporary files or disk I/O (in-memory only)
10. ✓ Builds and runs on Windows with administrator privileges

---

## Known Limitations

- **Registry hive format complexity:** Reconstructing the binary format accurately requires careful handling of internal structures, offsets, and checksums
- **Memory usage:** Entire hives held in memory (typically <100MB for SAM/SYSTEM/SECURITY combined)
- **Live hive consistency:** Registry hives are read while live (may see inconsistent state if being written to concurrently, but this is acceptable for backup purposes)
- **No incremental backup:** Always exports full hives; incremental logic must be handled by caller
- **Plaintext credentials:** Username/password visible in process listing; consider credential manager integration for future versions

---

## Dependencies

**Rust:**
- Edition: 2021
- `windows-sys = "0.52"` with features:
  - `Win32_Foundation` (HANDLE, types)
  - `Win32_System_Registry` (RegOpenKeyEx, RegEnumKeyEx, RegQueryValueEx, RegCloseKey)
  - `Win32_NetworkManagement_IpHelper` (WNetAddConnectionW for SMB)
  - `Win32_Storage_FileSystem` (CreateFileW, WriteFile for SMB writes)

---

## Testing Strategy (Not in Scope, but Noted)

1. **Unit:** Compile without errors or warnings
2. **Integration (manual):**
   - Run on domain controller with elevated privileges
   - Verify three .bin files created on SMB share
   - Verify files are readable and contain binary registry data (magic bytes: "regf")
   - Test failure scenarios:
     - No SMB path provided → exit with appropriate code
     - Wrong credentials → exit 3
     - Insufficient privileges → exit 2
     - Invalid SMB path → exit 4
   - Verify exported hives can be imported via `reg.exe import`

---

## Open Questions / Deferred

None — specification is complete and unambiguous.
