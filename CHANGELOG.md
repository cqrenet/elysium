# Changelog

All notable changes to the Elysium project are documented in this file.

Starting with **v2.2.0**, Elysium uses a **unified project version**. All scripts, settings templates, and documentation share the same version number so operators can verify consistency at a glance. Releases prior to v2.2.0 used per-script versioning; those entries are preserved below under their original dates.

---

## [Unreleased]

### Fixed
- `README.md` swapped the menu numbers for Lithnet (documented as 5) and Uninstall (documented as 4), and `Uninstall.ps1` had no confirmation, so an operator following the README to update the Lithnet store recursively deleted the whole install directory, reports included. The README and the `Elysium.ps1` help block now match the menu, and `Uninstall.ps1` requires typing `YES` (or `-Force` for unattended use).
- `decrypt.py` could not decrypt any current export: it did not recognize `ELY2` (so v2.4.6 files fell through to the legacy branch), and its `ELY1` branch used pycryptodome's default PBKDF2 PRF (HMAC-SHA1) while `Extract-NTHashes.ps1` has always used HMAC-SHA256. It now reads `ELY2` (verifying the HMAC before decrypting), `ELY1`, and the legacy format; encodes the passphrase as UTF-8 to match .NET; prompts for the passphrase without echo; refuses input that does not end in `.enc` instead of overwriting it; and exits non-zero on failure. New `tests/test_decrypt.py` round-trips through the real PowerShell encryptor.
- `Test-WeakADPasswords.ps1` did not relaunch under Windows PowerShell like `Extract-NTHashes.ps1` does, so a direct run under `pwsh` loaded DSInternals through `-UseWindowsPowerShell` implicit remoting, which returns deserialized objects. It also set the PSGallery repository to `Trusted` on the host as a side effect of installing DSInternals; that is removed (`-Force` on the install already covers the prompt).
- `Update-LithnetStore.ps1` ignored `InstallationPath`/`WeakPasswordsDatabase` and always looked for `khdb.txt` next to the script; it now resolves the same KHDB path as the other scripts. It also writes a transcript to `Reports/logs/` like the other operational scripts and uses the shared settings parser instead of its own copy.

## [2.4.6] — 2026-07-29

### Fixed
- `Uninstall.ps1` used `Get-Location` (the caller's working directory) instead of `$PSScriptRoot`, so running it from any CWD other than the install folder recursively force-deleted the wrong directory. The accompanying self-delete workaround was also broken (a `-Exclude` that could never match, a deferred `Start-Process` command line that couldn't bind its argument) and has been replaced with a plain recursive delete, since PowerShell holds no open handle on a script it has already read into memory.
- `Elysium.ps1` echoed the AES export passphrase to the console (`Read-Host` without `-AsSecureString`) and stored it in plaintext in `HKCU\Environment`. It's now DPAPI-protected via `ConvertFrom-SecureString` and never appears in plaintext at rest; `Extract-NTHashes.ps1` decrypts it back only in memory right before use.
- `Test-ReplicationPermissions` resolved the caller's SID/tokenGroups by stripping a `DOMAIN\` prefix from the credential username, so a UPN-formatted credential (`user@domain.tld`) had nothing to strip, the AD lookup threw, and the entire DCSync ACL pre-check was silently skipped. Now handles `DOMAIN\user`, `user@domain.tld`, and bare `sAMAccountName` correctly, and also disposes the `DirectoryEntry`/ADSI objects it creates.
- `Elysium.ps1`'s main menu had no `catch` around the switch statement, so any error re-thrown by a sub-script (bad credentials, unreachable DC, etc.) killed the whole orchestrator instead of returning to the menu.
- `Extract-NTHashes.ps1`: the temp directory holding plaintext NTLM hashes (before AES encryption) now has its ACL restricted to the current user; a checksum mismatch after upload now deletes the corrupt remote blob instead of leaving it live under its normal name; the plaintext export is now pinned to UTF-8 instead of depending on the PowerShell host; `Protect-FileWithAES`'s output format changed from `ELY1` to `ELY2`, adding an HMAC-SHA256 trailer (encrypt-then-MAC) so a wrong passphrase or tampered/corrupted ciphertext is detected instead of silently decrypting to garbage - **this is a breaking format change for any external decryption tooling**, see the README for the new layout.
- `Update-KHDB.ps1`: `Validate-Manifest` hardcoded `shardSize` to exactly `2`, rejecting manifests produced with any other value from `Prepare-KHDBStorage.ps1`'s supported 1-8 range; KHDB backups (`khdb.txt.bak-*`) accumulated forever with no retention policy (now capped at the 5 most recent); `Invoke-DownloadWithRetry` never disposed the `HttpResponseMessage` it got from each shard download.
- `Prepare-KHDBStorage.ps1`: `Split-KhdbIntoShards`'s fast path for plain 32-hex-char lines wrote straight through with no deduplication (unlike the slow path's adjacent-duplicate merge); fixing that surfaced a second bug where the valid-entry counter was a plain scalar mutated inside a scriptblock invoked via the call operator (`&`), which runs in its own child scope, so the increments were silently discarded and `TotalEntries`/checkpoint `validEntries`/live progress were all wrong on every run (moved onto the existing `$meta` hashtable, which mutates by reference). Also rejects manifest shard names (`-UploadOnly` mode) that resolve outside the shard root, closing a path-traversal gap for a tampered local `manifest.json`.
- `Test-WeakADPasswords.ps1`: report generation piped results through `Out-String` without `-Width`, so a long `SamAccountName` could be truncated by the default formatter width and silently drop its `UPN:` annotation in the report.

## [2.4.5] — 2026-07-29

### Fixed
- `Test-ReplicationPermissions` now detects explicit **Deny** ACEs on the replication extended rights, not just missing Allow grants. Previously the pre-flight check only scanned `Allow` ACEs, so an explicit Deny (common in hardening baselines that Deny a broad group like `Everyone`/`Domain Users` the replication rights and Allow only named DCSync accounts) was invisible to the check: it reported "verified" while `Get-ADReplAccount` still failed with "Replication access was denied". The check now flags exactly which right is blocked and by which identity's Deny ACE.

### Changed
- README *Common errors* section expanded with a dedicated troubleshooting flow for "pre-flight passed but DCSync still denied" (RODC target, unconverged ACL replication, cross-domain group scope, and how to get a definitive answer via Event ID 4662 auditing).

---

## [2.4.4] — 2026-06-15

### Fixed
- `Test-ReplicationPermissions` now checks **both** the domain NC (`DC=…`) and the schema NC (`CN=Schema,CN=Configuration,DC=…`) for the required DCSync extended rights. DSInternals 7.0 changed schema fetching from LDAP to DRS (`GetNCChanges`), so the schema NC now requires its own ACL entry. Previously the pre-flight check passed (domain NC rights present) while `Get-ADReplAccount` immediately failed at `FetchSchema()` with "Replication access was denied".
- The `Replication access was denied` catch block in `Test-WeakADPasswords` now emits a structured, actionable error message that names the exact DNs to target and explains the DSInternals 7.0 schema NC change, replacing the previous generic "ensure this account has replication rights on the domain" message.
- Diagnostic dump (`dcsync-diag-*.txt`) now includes a `SchemaDN` field so the schema NC path is immediately visible when triaging a dump.

### Changed
- Least-privilege requirement updated: the DCSync service account now needs the three replication extended rights on **both** the domain NC *and* `CN=Configuration,DC=…` (which covers the schema NC via inheritance). See *Least privileges* in the README for delegation steps.

---

## [2.4.3] — 2026-06-09

### Fixed
- Replaced the `DirectoryEntry` + `RefreshCache` tokenGroups retrieval in `Test-ReplicationPermissions` with `Get-ADUser -Properties tokenGroups`. The previous `DirectoryEntry` approach was broken by the v2.4.1 URI-escaping "fix" (`EscapeDataString` produces percent-encoded paths that ADSI `DirectoryEntry` cannot parse, causing "invalid dn syntax" errors).
- Removed `EscapeDataString` from the ACL-reading `DirectoryEntry` path in `Test-ReplicationPermissions` as well, since `DirectoryEntry` expects raw LDAP path syntax, not URI encoding.

---

## [2.4.2] — 2026-06-09

### Fixed
- Replaced UTF-8 em-dashes (`\u2014`) in `Elysium.Common.ps1` and `Bump-Version.ps1` with ASCII hyphens. On Windows PowerShell without a UTF-8 BOM, the three-byte em-dash sequence was misinterpreted as containing a quote character, causing cascading parse errors (unexpected token, missing closing `)`/`}`/`catch`, etc.).

---

## [2.4.1] — 2026-06-09

### Fixed
- `Test-ReplicationPermissions` and `Test-DCClockSkew` now URI-escape Distinguished Names via `[System.Uri]::EscapeDataString` before embedding them in `DirectoryEntry` LDAP URLs. DNs containing `/`, `#`, or other reserved characters previously caused URL mis-parsing and constructor failures.

---

## [2.4.0] — 2026-06-09

### Added
- **DC clock skew pre-flight check** (`Test-DCClockSkew` in `Elysium.Common.ps1`): compares the local machine clock against the target DC's `RootDSE.currentTime` before attempting DCSync. Warns if skew exceeds 300s (Kerberos hard limit) or 60s (approaching limit), and provides the `w32tm /resync /force` remediation command.
- **SDProp protection warning** in `Test-ReplicationPermissions`: detects `adminCount=1` on the service account and warns that SDProp runs every 60 minutes and may silently revert replication rights or group memberships.
- **Protected Users group warning** in `Test-ReplicationPermissions`: detects membership in the Protected Users group (RID 525) and warns that it restricts Kerberos delegation and RC4 authentication required by DSInternals for DRS replication.

### Fixed
- DSInternals auto-update flow now uses `Install-Module -Force -AllowClobber` instead of `Update-Module` to avoid a PowerShellGet bug where null `PublishedDate` metadata causes "cannot convert null to type system.datetime".

---

## [2.3.0] — 2026-06-09

### Added
- `Test-WeakADPasswords.ps1` now checks the installed DSInternals version at startup:
  - **v6.2** (unsigned) is flagged with a warning explaining that unsigned native DLLs are blocked and replication will fail. Remediation: `Update-Module DSInternals`.
  - **Below v7.0** triggers an interactive prompt offering to run `Update-Module DSInternals -Force` automatically. If accepted, the script updates the module and exits cleanly so the operator can re-run with the new version loaded.
  - v7.0+ is required because it fixes intermittent CRC errors mid-replication and `Test-PasswordQuality` result truncation bugs.

---

## [2.2.5] — 2026-06-09

### Fixed
- The DSInternals `Zone.Identifier` block error message (added in v2.2.4) now dynamically resolves the actual DSInternals module path via `Get-Module` instead of hardcoding `$env:ProgramFiles\WindowsPowerShell\DSInternals`. The `Unblock-File` command in the error now points to the correct installation directory.

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
