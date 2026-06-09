# Changelog

All notable changes to the Elysium project are documented in this file.

Starting with **v2.2.0**, Elysium uses a **unified project version**. All scripts, settings templates, and documentation share the same version number so operators can verify consistency at a glance. Releases prior to v2.2.0 used per-script versioning; those entries are preserved below under their original dates.

---

## [2.2.4] — 2026-06-09

### Fixed
- `Test-ReplicationPermissions` (in `Elysium.Common.ps1`) now skips `InheritOnly` ACEs when evaluating replication rights. An ACE marked `InheritOnly` applies only to child objects, not the domain root itself, so it does not grant the required extended rights for DCSync on the domain object.
- `Import-CompatModule` (in `Test-WeakADPasswords.ps1`) now detects DSInternals being blocked by Windows `Zone.Identifier` (alternate data stream from internet download) and throws a clear, actionable error with the exact `Unblock-File` command to run. Previously this surfaced as an opaque non-FIPS warning.

---

## [2.2.3] — 2026-06-09

### Fixed
- `Test-ReplicationPermissions` (in `Elysium.Common.ps1`) now correctly recognizes `GenericAll` and blanket `ExtendedRight` (empty ObjectType) ACEs as satisfying replication permission requirements. Previously, only exact GUID-matched ExtendedRight ACEs were detected, causing false negatives when rights were granted via broader permissions.
- Improved error diagnostics: the missing-rights message now indicates whether an ACE for the specific right exists on the domain object but is not assigned to the caller, versus no ACE existing at all.

---

## [2.2.2] — 2026-06-09

### Fixed
- `Test-ReplicationPermissions` (in `Elysium.Common.ps1`) now resolves the caller's **effective token SIDs** via the `tokenGroups` constructed attribute instead of walking `MemberOf` directly. This correctly accounts for nested group memberships and avoids false-positive "missing permissions" errors when the account is entitled through nested groups.

---

## [2.2.1] — 2026-06-09

### Changed
- **DRY refactoring — shared helpers consolidated into `Elysium.Common.ps1`:**
  - Moved `Read-KeyValueSettingsFile`, `Read-ElysiumSettings`, and `Get-SettingsValue` from `Prepare-KHDBStorage.ps1` and `Update-KHDB.ps1` into the common helper.
  - Moved `Build-BlobUri` and Azure URI helpers from `Update-KHDB.ps1` into the common helper.
  - Moved `Get-FunctionDefinitionText` from all scripts that duplicated it into the common helper.
  - Moved `Get-ValidatedADCredential` and `Test-ReplicationPermissions` from `Test-WeakADPasswords.ps1` into the common helper.
  - Moved all native S3 SigV4 helpers (`Ensure-AWSS3Module`, `New-S3Client`, `HmacSha256`, `GetSignatureKey`, `BuildAuthHeaders`, `BuildS3Uri`, etc.) from `Extract-NTHashes.ps1` into the common helper.
- `Test-WeakADPasswords.ps1` and `Extract-NTHashes.ps1` now import `Elysium.Common.ps1` (they previously did not), reducing duplication and ensuring consistent behavior.
- `Update-KHDB.ps1` and `Prepare-KHDBStorage.ps1` removed their local copies of helpers already available in the common module.
- Removed legacy `Settings.ps1` (superseded by `ElysiumSettings.txt`).
- Minor cleanup: removed stray placeholder comment in `Elysium.ps1`.

---

## [2.2.0] — 2026-06-09

### Changed
- **Unified versioning:** All PowerShell scripts, the settings template, and documentation now share a single project version (`2.2.0`). This replaces the previous per-script versioning model.

### Test-WeakADPasswords.ps1
- Added `Test-ReplicationPermissions` helper that validates the three required AD replication extended rights (`Replicating Directory Changes`, `Replicating Directory Changes All`, `Replicating Directory Changes In Filtered Set`) against the domain object's DACL before attempting DCSync. Missing permissions now produce a clear, fail-fast error instead of an opaque `Access is denied` later in the workflow.

---

## Historical Releases (per-script versioning)

### 2026-03-16

#### Test-WeakADPasswords.ps1 v1.4.5
Fixed:
- Normalizes legacy `HASH:count` KHDB files into a temporary hash-only list before calling `DSInternals`, so dictionary matches no longer fail silently when clients have older database content.
- Warns when KHDB normalization is required instead of leaving the weak-password match section empty without explanation.

#### Update-KHDB.ps1 v2.1.1
Fixed:
- Rebuilds the merged local `khdb.txt` as a DSInternals-compatible hash-only file even when upstream shards still contain legacy `HASH:count` lines.
- Tightened KHDB merge validation so malformed shard content is surfaced during update rather than producing a silently unusable weak-password database.

#### Prepare-KHDBStorage.ps1 v1.1.1
Fixed:
- Accepts legacy `HASH:count` source input but writes deduplicated hash-only shards for downstream DSInternals consumers.

#### README.md
Changed:
- Corrected the KHDB format documentation to require one NT hash per line and documented the automatic legacy-format normalization.

### 2026-02-17

#### Test-WeakADPasswords.ps1 v1.4.4
Changed:
- Added startup FIPS policy detection (`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled`) with fail-fast behavior and explicit remediation steps to avoid opaque DSInternals runtime failures.

#### Test-WeakADPasswords.ps1 v1.4.3
Fixed:
- Added explicit handling for `Microsoft.PowerShell.Commands.WriteErrorException,DSInternals.Bootstrap.psm1` so known FIPS bootstrap errors are downgraded to a controlled warning when possible, with a clear fail message if DSInternals cannot load under policy.

#### Test-WeakADPasswords.ps1 v1.4.2
Fixed:
- DSInternals module import now handles the known FIPS bootstrap warning as non-fatal when the module successfully loads, preventing repeated `SecurityError` noise during startup.

#### Test-WeakADPasswords.ps1 v1.4.1
Changed:
- Added credential pre-validation against the selected domain controller before running `Get-ADReplAccount`, including retry prompts for rejected credentials.
- Improved error diagnostics to distinguish invalid credentials from missing replication permissions (`Access is denied`).
- Added optional `-Credential` parameter to `Test-WeakADPasswords` for callers that need to provide credentials non-interactively.

#### README.md
Changed:
- Updated weak-password testing documentation to reflect credential pre-check behavior and added a short troubleshooting section for common authentication/permissions failures.

### 2025-10-30

#### Update-KHDB.ps1 v2.0.0
Changed:
- Replaced single-archive workflow with manifest-driven, two-hex shard downloads that verify SHA256/size before in-place updates.
- Added incremental refresh logic, stale shard cleanup, and automatic rebuild of the merged `khdb.txt` for downstream scripts.
- Hardened validation to stream-check merged output while preserving strict TLS, retry, and transcript behaviour.

#### ElysiumSettings.txt.sample v1.3.0
Added:
- Documented `KhdbManifestPath`, `KhdbShardPrefix`, and `KhdbLocalShardDir` defaults for the shard-aware updater.

#### README.md
Changed:
- Described the manifest/shard update flow so operators understand the incremental download model and automatic cleanup.

#### Prepare-KHDBStorage.ps1 v1.0.0
Added:
- Helper script to split `khdb.txt` (or a directory/list of `.gz` HIBP slices) into two-hex shards, build the JSON manifest, and push the package to Azure Blob Storage or S3-compatible endpoints.
- Validation step that tallies and quarantines malformed hashes before sharding, writing `invalid-hashes.txt` plus a console summary so bad data never reaches storage.
- Optional `-ShowProgress` mode emitting periodic `Write-Progress` updates (interval configurable) so large ingests visibly tick forward.
- Automatic reconstruction of HIBP NTLM hashes (file-prefix + suffix) so partially stored hashes still produce full 32-hex values in the shards, plus per-prefix deduplication that keeps the highest observed count.
- `-ForcePlainText` switch to skip `.gz` expansions entirely and treat the source as pre-built hash lines (skipped entries are reported separately).
- Emits a merged `khdb-clean.txt` alongside the shards for DSInternals or offline review, including SHA256 fingerprints for both manifest and clean output.
- Automatic checkpoint/resume when `-ForcePlainText` is used (configurable via `-CheckpointPath`, disable with `-NoCheckpoint`) so large ingests can be paused and resumed without reprocessing prior shards.

### 2025-10-26

#### Test-WeakADPasswords.ps1 v1.3.3
Added:
- Opt-in usage beacon that fires a single HTTP request (GET/POST/PUT) after settings load, suitable for pre-signed S3 URLs, and only includes script name, version, and a UTC timestamp (plus optional instance ID).
- Instance identifier header/body support and configurable timeout so adopters can differentiate deployments without collecting user data.

#### ElysiumSettings.txt.sample v1.2.0
Added:
- Documented `UsageBeacon*` keys (URL, method, instance ID, timeout) so telemetry stays disabled by default but easy to enable.

#### README.md
Added:
- Usage beacon section explaining how to configure the lightweight tracking call and what metadata is transmitted.

### 2025-10-21

#### Extract-NTHashes.ps1 v1.2.1
Fixed:
- Corrected SigV4 host header formatting so non-default ports serialize without parser errors.
- Hardened hashing helpers to avoid `ComputeHash` overload ambiguity under Windows PowerShell.
- Domain selection menu now respects the configured numeric order.

#### Test-WeakADPasswords.ps1 v1.3.2
Changed:
- Switched to the sorted KHDB path when driving `Test-PasswordQuality`, eliminating full linear scans and avoiding malformed-line crashes on massive datasets.

#### Test-WeakADPasswords.ps1 v1.3.1
Fixed:
- Domain picker now renders in numeric order from settings for predictable operator workflows.
- UPN export now relies on structured weak-password results, so dictionary hit UPN lists are populated reliably.

### 2025-10-10

#### Test-WeakADPasswords.ps1 v1.3.0
Added:
- `CheckOnlyEnabledUsers` flag wired from settings to filter accounts prior to `Test-PasswordQuality`.
- Transcript logging to `Reports/logs/test-weakad-<timestamp>.log`.

#### Extract-NTHashes.ps1 v1.2.0
Added:
- Transcript logging to `Reports/logs/extract-hashes-<timestamp>.log`.

#### Elysium.ps1 v1.1.0
Updated:
- Added strict error handling (`$ErrorActionPreference='Stop'`) and `Set-StrictMode`.
- Resolved script invocations via `$PSScriptRoot` to avoid CWD issues.

#### Elysium.ps1 v1.2.0
Added:
- Transcript logging to `Reports/logs/orchestrator-<timestamp>.log` and graceful shutdown without `exit`.

#### Uninstall.ps1 v1.1.0
Added:
- Transcript logging to `%TEMP%/Elysium/logs/uninstall-<timestamp>.log` so logs persist after directory removal.

#### Update-KHDB.ps1 v1.1.0
Added/Updated:
- Robust settings validation and SAS token normalization.
- Safe URL construction with `UriBuilder` and custom User-Agent.
- TLS 1.2 enforced; `HttpClient` timeout and retry with backoff for transient errors.
- Download progress for both known and unknown content length.
- Atomic-ish update: download to temp, extract, validate, backup existing `khdb.txt`, then replace.
- KHDB validation: format check (32-hex), deduplication and normalization.
- Transcript logging to `Reports/logs/update-khdb-<timestamp>.log`.

#### Test-WeakADPasswords.ps1 v1.2.0
Updated:
- Enforced modules via `#Requires`; removed runtime installs.
- Added strict mode and error preference.
- Resolved paths relative to `$PSScriptRoot` (settings, KHDB, reports).
- Ensured report directory creation and sane defaults (`Reports`).
- Removed stray top-level loop; UPN enrichment occurs during report generation only.

#### Extract-NTHashes.ps1 v1.1.0
Updated:
- Enforced modules via `#Requires`; added strict mode.
- Fixed variable ordering bug and unified filename scheme with domain prefix.
- Implemented PBKDF2 (HMAC-SHA256, 100k iterations) + random salt for AES-256-CBC encryption; header `ELY1|salt|iv`.
- Normalized SAS token and verified container existence; checksum verified before cleanup; artifacts retained on failure.
- Paths resolved relative to `$PSScriptRoot`; ensured report base directory exists.

#### ElysiumSettings.txt.sample v1.1.0
Updated:
- `ReportPathBase` default changed to `Reports` (relative) and added guidance on required modules and replication rights.
- Added optional `CheckOnlyEnabledUsers=true` example flag.

### Extract-NTHashes.ps1

#### version 1.1.1
**Updated:**
- UPNs of the accounts with passwords found in dictionary were moved into separate report (one UPN at a line) to enable further automation.

#### version 1.1.0
**Added:**
- UPN retrieval (this will prolong the time needed to run the script significantly)
- Better error handling
