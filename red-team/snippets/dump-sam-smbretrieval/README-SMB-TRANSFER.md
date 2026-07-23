# SAM Hives SMB Transfer Tool

Transfers Windows SAM, SYSTEM, and SECURITY registry hives to an SMB share backup location.

## Usage

Run with administrator or SYSTEM privileges:

```powershell
.\smb-transfer.exe \\backup-server\hives\dc01 domain\admin password
```

## Parameters

- **SMB Path** — UNC path to backup directory (e.g., `\\server\share\backups`)
- **Username** — SMB authentication username (e.g., `domain\admin`)
- **Password** — SMB authentication password (plaintext; visible in history)

## Exit Codes

- **0** — Success; all three hives transferred
- **1** — Hive file not found locally
- **2** — Access denied (insufficient privileges)
- **3** — SMB authentication failed (wrong credentials)
- **4** — SMB path not found or unreachable
- **5** — SMB write failed (permissions, disk space)
- **6** — Other errors (unexpected Windows/network failure)

## Example: Automated Backup Script

```powershell
# Backup SAM hives to central NAS
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "\\nas\domain_backups\$env:COMPUTERNAME\$timestamp"

# Create backup directory
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Transfer hives
.\smb-transfer.exe $backupDir backup_user backup_password

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Hives backed up successfully"
} else {
    Write-Error "Hive backup failed (code $LASTEXITCODE)"
    exit $LASTEXITCODE
}
```

## Notes

- **Requires elevation:** Run as administrator or SYSTEM
- **SAM locking:** The hives are locked by lsass.exe on running systems. Success requires:
  - Running as SYSTEM with backup privileges
  - Using VSS snapshots
  - Running during maintenance
- **Overwrite behavior:** Existing files on the share are replaced without warning
- **Silent operation:** No output except exit codes; integrate with logging externally
