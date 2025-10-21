# Changelog

## 2025-10-21

### Extract-NTHashes.ps1 v1.2.1
Fixed:
- Corrected SigV4 host header formatting so non-default ports serialize without parser errors.
- Hardened hashing helpers to avoid `ComputeHash` overload ambiguity under Windows PowerShell.
- Domain selection menu now respects the configured numeric order.

### Test-WeakADPasswords.ps1 v1.3.1
Fixed:
- Domain picker now renders in numeric order from settings for predictable operator workflows.

## 2025-10-10

### Test-WeakADPasswords.ps1 v1.3.0
Added:
- `CheckOnlyEnabledUsers` flag wired from settings to filter accounts prior to `Test-PasswordQuality`.
- Transcript logging to `Reports/logs/test-weakad-<timestamp>.log`.

### Extract-NTHashes.ps1 v1.2.0
Added:
- Transcript logging to `Reports/logs/extract-hashes-<timestamp>.log`.

### Elysium.ps1 v1.1.0
Updated:
- Added strict error handling (`$ErrorActionPreference='Stop'`) and `Set-StrictMode`.
- Resolved script invocations via `$PSScriptRoot` to avoid CWD issues.

### Elysium.ps1 v1.2.0
Added:
- Transcript logging to `Reports/logs/orchestrator-<timestamp>.log` and graceful shutdown without `exit`.

### Uninstall.ps1 v1.1.0
Added:
- Transcript logging to `%TEMP%/Elysium/logs/uninstall-<timestamp>.log` so logs persist after directory removal.

### Update-KHDB.ps1 v1.1.0
Added/Updated:
- Robust settings validation and SAS token normalization.
- Safe URL construction with `UriBuilder` and custom User-Agent.
- TLS 1.2 enforced; `HttpClient` timeout and retry with backoff for transient errors.
- Download progress for both known and unknown content length.
- Atomic-ish update: download to temp, extract, validate, backup existing `khdb.txt`, then replace.
- KHDB validation: format check (32-hex), deduplication and normalization.
- Transcript logging to `Reports/logs/update-khdb-<timestamp>.log`.

### Test-WeakADPasswords.ps1 v1.2.0
Updated:
- Enforced modules via `#Requires`; removed runtime installs.
- Added strict mode and error preference.
- Resolved paths relative to `$PSScriptRoot` (settings, KHDB, reports).
- Ensured report directory creation and sane defaults (`Reports`).
- Removed stray top-level loop; UPN enrichment occurs during report generation only.

### Extract-NTHashes.ps1 v1.1.0
Updated:
- Enforced modules via `#Requires`; added strict mode.
- Fixed variable ordering bug and unified filename scheme with domain prefix.
- Implemented PBKDF2 (HMAC-SHA256, 100k iterations) + random salt for AES-256-CBC encryption; header `ELY1|salt|iv`.
- Normalized SAS token and verified container existence; checksum verified before cleanup; artifacts retained on failure.
- Paths resolved relative to `$PSScriptRoot`; ensured report base directory exists.

### ElysiumSettings.txt.sample v1.1.0
Updated:
- `ReportPathBase` default changed to `Reports` (relative) and added guidance on required modules and replication rights.
- Added optional `CheckOnlyEnabledUsers=true` example flag.

## Extract-NTHashes.ps1 

### version 1.1.1
**Updated:**
- UPNs of the accounts with passwords found in dictionary were moved into separate report (one UPN at a line) to enable further automation.

### version 1.1.0
**Added:**
- UPN retrieval (this will prolong the time needed to run the script significantly)
- Better error handling
