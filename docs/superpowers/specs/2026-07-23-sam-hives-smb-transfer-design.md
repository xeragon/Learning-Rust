# SAM Hives SMB Transfer Tool — Design Spec

**Date:** 2026-07-23  
**Project:** dump-sam-smbretrieval (SMB Transfer Feature)  
**Scope:** Transfer Windows SAM, SYSTEM, and SECURITY registry hives to an SMB share for backup

---

## Overview

An enhancement to the existing SAM hive loader that skips memory mapping and instead transfers three critical registry hives (SAM, SYSTEM, SECURITY) directly to an SMB backup share. This tool is intended for domain controller backup workflows where hive extraction must be centralized on a network share for later processing.

**Target environment:** Windows domain controller (or any system with administrator/SYSTEM privileges)

**Design principle:** Sequential transfer for simplicity and clear error semantics; silent operation (exit codes only) for script integration.

---

## Requirements

### Functional
1. Accept SMB share path, username, and password as command-line arguments
2. Locate the three hive files locally: `%systemroot%\System32\config\SAM`, `SYSTEM`, `SECURITY`
3. Open each hive file for reading (handle file locking gracefully)
4. Establish authenticated connection to the SMB share
5. Transfer each hive to the share with auto-generated filenames: `SAM.bin`, `SYSTEM.bin`, `SECURITY.bin`
6. Exit with code 0 on complete success; exit with error code on any failure
7. Overwrite existing files on the share (no conflict detection)

### Non-Functional
- **Silent operation:** No console output; exit code alone indicates success/failure
- **Error handling:** Fail fast (stop at first error), exit cleanly with appropriate code
- **No persistence:** Temporary SMB connection only; credentials not cached or stored
- **Sequential transfer:** Transfer hives one at a time for predictable error handling
- **Privilege assumption:** Program assumes it runs with administrator/SYSTEM privileges
- **No compression:** Transfer raw binary hive files

---

## Architecture

### Single Responsibility
One executable with one function: read three local hive files → authenticate to SMB → transfer sequentially → exit

### Data Flow
```
Command: dump-sam-smbretrieval.exe \\server\share\path username password
    ↓
1. Parse command-line arguments (path, username, password)
    ↓
2. Locate hive files in %systemroot%\System32\config\
    - SAM
    - SYSTEM
    - SECURITY
    ↓
3. Attempt to open SAM file (read-only)
    ↓
4. Establish SMB connection with provided credentials
    ↓
5. Transfer SAM → SAM.bin
    ↓
6. Transfer SYSTEM → SYSTEM.bin
    ↓
7. Transfer SECURITY → SECURITY.bin
    ↓
Exit 0 (success) or error code (failure, silent)
```

### Components

**1. Command-Line Parser**
- Input: `<smb_path> <username> <password>`
- Output: Validated parameters or exit 6 (invalid args)
- Responsible for: Parsing three required arguments

**2. Hive Locator**
- Input: None (hardcoded paths)
- Output: Full paths to SAM, SYSTEM, SECURITY files
- Responsible for: Locating hives in `%systemroot%\System32\config\`

**3. File Reader**
- Input: Hive file path
- Output: Open file handle or error code (1 = not found, 2 = access denied, 6 = other)
- Responsible for: Opening hive files read-only; mapping Windows errors

**4. SMB Connector**
- Input: SMB path, username, password
- Output: Authenticated connection handle or error code (3 = auth failed, 4 = path not found, 6 = other)
- Responsible for: Connecting to SMB share with credentials; handling auth/network errors

**5. File Transfer**
- Input: Local file handle, SMB connection, target filename
- Output: Success or error code (5 = write failed, 6 = other)
- Responsible for: Reading local file, writing to SMB, handling transfer errors

**6. Error Handler**
- Input: Windows/network error codes
- Output: Program exit code (1-6)
- Responsible for: Mapping internal errors to user-facing exit codes

---

## Technical Details

### Windows API Calls Required
1. **GetSystemWindowsDirectoryW** — Locate `%systemroot%`
2. **CreateFileW** — Open hive files (SAM, SYSTEM, SECURITY)
3. **ReadFile** — Read hive file contents
4. **CloseHandle** — Clean up file handles

### SMB/Network API Calls Required
1. **WNetAddConnection2** or equivalent — Connect to SMB share with credentials
2. **CreateFileW** (for SMB path) — Open/create file on share
3. **WriteFile** — Write hive data to share
4. **CloseHandle** — Clean up SMB connection

### Hive File Locations
```
%systemroot%\System32\config\SAM       → SAM hive
%systemroot%\System32\config\SYSTEM    → SYSTEM hive
%systemroot%\System32\config\SECURITY  → SECURITY hive
```

All three must be accessible for success; any missing or inaccessible results in exit code 1 or 2.

### SMB Connection Lifetime
- Establish connection once (per `WNetAddConnection2` or equivalent)
- Use for all three transfers
- Disconnect at end or on first error
- Credentials passed at connection time; never stored or cached

### File Transfer Strategy (Sequential)
1. Open local hive file → read full contents into memory
2. Write to SMB: `\\server\share\path\SAM.bin`
3. Close both files
4. Repeat for SYSTEM, SECURITY
5. On any error, abort and exit with error code

**Rationale:** Sequential is simpler than parallel; memory overhead acceptable for registry hives (typically <100MB total); clear error semantics.

### Error Handling & Exit Codes

| Exit | Meaning | Scenario |
|------|---------|----------|
| 0 | Success | All three hives transferred |
| 1 | Hive not found | SAM/SYSTEM/SECURITY not in config directory |
| 2 | Access denied | Insufficient privilege to read hives |
| 3 | SMB auth failed | Username/password incorrect or user disabled |
| 4 | SMB path not found | Share path unreachable or doesn't exist |
| 5 | SMB write failed | Insufficient disk space, permissions, or I/O error |
| 6 | Other errors | Unexpected Windows/network failure |

**Behavior:**
- Fail fast: Exit at first error, do not attempt remaining hives
- Silent: No error message output; exit code alone
- No retry: Caller can implement retry logic if needed

---

## Usage

### Command Syntax
```
dump-sam-smbretrieval.exe <smb_path> <username> <password>
```

### Parameters
- `<smb_path>` — UNC path to SMB share backup directory (e.g., `\\backup-server\hives\dc01`)
- `<username>` — Username for SMB authentication (e.g., `domain\admin` or `admin`)
- `<password>` — Password for SMB authentication (plaintext; passed as argument)

### Examples

**Example 1: Basic usage**
```powershell
.\dump-sam-smbretrieval.exe \\backup-server\hives\dc01 domain\admin P@ssw0rd
if ($LASTEXITCODE -eq 0) {
    Write-Host "Hives backed up successfully"
} else {
    Write-Host "Backup failed with code $LASTEXITCODE"
}
```

**Example 2: With IP address**
```powershell
.\dump-sam-smbretrieval.exe \\10.0.0.50\share\backups admin password123
```

**Example 3: In AD backup script**
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "\\nas\domain_backups\$env:COMPUTERNAME\$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

.\dump-sam-smbretrieval.exe $backupDir backup_user backup_password
$result = $LASTEXITCODE

if ($result -ne 0) {
    # Log error and abort
    Write-Error "SAM hive backup failed (code $result)"
    exit $result
}

# Continue with NTDS.dit and other backup steps
```

---

## Success Criteria

1. ✓ Program accepts three command-line arguments (SMB path, username, password)
2. ✓ Locates SAM, SYSTEM, SECURITY hives in `%systemroot%\System32\config\`
3. ✓ Opens hive files with read-only access
4. ✓ Authenticates to SMB share with provided credentials
5. ✓ Transfers all three hives sequentially
6. ✓ Creates files with names: `SAM.bin`, `SYSTEM.bin`, `SECURITY.bin`
7. ✓ Exits with 0 on complete success
8. ✓ Exits with correct error code (1-6) on any failure
9. ✓ Silent operation: no output except exit code
10. ✓ Overwrites existing files without prompting

---

## Known Limitations

- **Plaintext passwords in arguments:** Passwords are visible in process listings and command history. This is intentional for scripting; consider credential manager integration in future versions.

- **SAM file locking:** The SAM, SYSTEM, and SECURITY hives are locked by lsass.exe on a running system. This program will fail with exit code 2 unless:
  - Running as SYSTEM or with special backup privileges
  - Using Volume Shadow Copy (VSS) snapshots
  - Running during a maintenance window when lsass is not holding an exclusive lock

- **No compression:** Hives are transferred as-is (binary, uncompressed). Caller can compress on the share if needed.

- **No incremental backup:** Always transfers full hives. Incremental backups require caller logic.

- **One invocation per backup:** No batching or scheduling built in; caller can wrap with scheduling tools (Task Scheduler, etc.).

---

## Dependencies

**Rust:**
- Edition: 2021
- `windows-sys = "0.52"` with features:
  - `Win32_Foundation` (HANDLE, LPWSTR, file constants)
  - `Win32_Storage_FileSystem` (CreateFileW, ReadFile, file I/O)
  - `Win32_System_SystemInformation` (GetSystemWindowsDirectoryW)
  - `Win32_System_Memory` (file mapping if needed for large reads)
  - `Win32_NetworkManagement_IpHelper` or `Win32_NetworkManagement_Rras` (SMB connection)

---

## Testing Strategy (Not in Scope, but Noted)

1. **Unit:** Compile without errors or warnings
2. **Integration (manual):**
   - Run on domain controller with elevated privileges
   - Provide valid SMB share path, username, password
   - Verify exit code 0 and three files on share (SAM.bin, SYSTEM.bin, SECURITY.bin)
   - Verify files are readable and contain binary hive data (magic bytes: "regf")
   - Test failure scenarios:
     - Invalid SMB path → exit 4
     - Wrong password → exit 3
     - No disk space on share → exit 5
     - No admin privilege → exit 2

---

## Open Questions / Deferred

None — specification is complete and unambiguous.
