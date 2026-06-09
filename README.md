# Elysium
## Summary
This tool is used for regular and ad-hoc checking of weak passwords in Active Directory domain. It is a collection of PowerShell scripts leveraging mainly tools from DSInternals suite. The output of this tool is report of weak passwords in the AD domain that warrant attention from internal security team.

Usage of this tool consists of three steps:
1. Update the known-hashes database (KHDB).
2. Test AD passwords against KHDB and generate weak passwords report.
3. Extract current hashes (without usernames) and securely send them for improving the KHDB.

Sensitive operations are confined only to the dedicated host. In the third step, only extracted hashes without usernames are tranferred (in compressed and encrypted form). This step is completely optional, but recommended as it enables the tool provider to update the KHDB.

## Prerequisities
* **Windows Host:** A Windows machine with PowerShell and DSInternals suite installed.
* **Administrative Access:** Local admin privileges on the host for installation and updating.
* **Domain Credentials:** For weak-password testing (option 2), an account with the three replication rights (`Replicating Directory Changes`, `Replicating Directory Changes All`, `Replicating Directory Changes In Filtered Set`) on the domain naming context; Domain Admin also works but is not required. Keep this account disabled and enable only when running tests.
* **Network Requirements:** A stable connection to the domain controller in each tested AD domain and internet access (specific hostnames/IP addresses will be provided).

## Versioning and Releases

Elysium uses a **unified project version** starting with v2.2.0. Every script, the settings template, and the documentation share the same version number so you can verify consistency at a glance by checking the header of any `.ps1` file. Releases are tagged in Git (`v<major>.<minor>.<patch>`) and documented in `CHANGELOG.md`.

Prior to v2.2.0, each script carried its own version number; those historical versions are preserved in the changelog for reference.

---
## Operation
### Install and update
This tool is provided in private git repository. Installation and updating is done with cloning and pulling from this repository.
During first run, the tool will ask for passphrase that will be used to encrypt/decrypt sensitive content.
After installation, edit ElysiumSettings.txt, check all variables and add domains to test.
All scripts automatically relaunch under PowerShell 7 (`pwsh`) when it is installed so that features like parallel transfers are available; if pwsh is missing they continue under Windows PowerShell 5.1 with the legacy single-threaded behavior. The two DSInternals-driven workflows (menu options 2 and 3) load the legacy `ActiveDirectory` and `DSInternals` modules, so they automatically fall back to Windows PowerShell even if pwsh is present.
### Update Known-Hashed Database (KHDB)
Run script Elysium.ps1 as an administrator and choose option 1 (Update Known-Hashes Database).
The updater now pulls a manifest plus individual hash shards (two-hex prefix layout) from the configured storage (Azure Blob or S3-compatible), verifies checksums, replaces only changed shards, and rebuilds `khdb.txt` for local use. Deleted shards listed in the manifest are removed automatically. When PowerShell 7 is available the downloader automatically fetches up to `-MaxParallelTransfers` shards in parallel (default `5`); on Windows PowerShell 5.1 it reverts to the original sequential behavior. Override the concurrency as needed when running the script directly (for example `.\Update-KHDB.ps1 -MaxParallelTransfers 8`).

To publish an updated shard set, run `Prepare-KHDBStorage.ps1` against your sorted `khdb.txt` (or point it at the directory/list of the Have I Been Pwned `.gz` slices). The helper reconstructs the full 32‑hex NTLM values (prefix + remainder), deduplicates per hash (keeping the largest count), splits by the first two hex characters, writes a manifest (`version`, `sha256`, `size`, entry counts), and can upload the resulting files directly to Azure Blob Storage (via SAS) or S3-compatible endpoints using SigV4. Invalid or malformed entries are omitted automatically, and a short report (aggregate counts + `invalid-hashes.txt`) is produced for review. Example:

```powershell
.\Prepare-KHDBStorage.ps1 -SourcePath .\khdb.txt `
    -OutputRoot .\publish `
    -StorageProvider S3 `
    -S3EndpointUrl https://s3.example.com `
    -S3BucketName private-khdb `
    -S3AccessKeyId AKIA... `
    -S3SecretAccessKey ... `
    -ManifestRemotePath khdb/manifest.json `
    -ShardRemotePrefix khdb/shards
```

Use `-SkipUpload` to stage files locally, or `-StorageProvider Azure` with `storageAccountName`/`containerName`/`sasToken` when targeting Azure Blob Storage. Add `-ShowProgress` (optionally tune `-ProgressUpdateInterval`) if you want a running `Write-Progress` indicator while the hashes are being split. Pass `-ForcePlainText` when your `khdb.txt` already contains complete hashes and you want `.gz` references treated as invalid instead of being expanded. When you only need to push an already prepared package, combine `-UploadOnly` with `-OutputRoot` pointing at the existing shard directory and choose the storage provider to perform an upload-only run. Missing storage values are pulled from `ElysiumSettings.txt` automatically (override the path with `-SettingsPath`) so you don’t have to retype S3/Azure credentials for every run. On PowerShell 7, `Prepare-KHDBStorage.ps1` can push shards concurrently by setting `-MaxParallelTransfers` (default `5`); Windows PowerShell 5.1 automatically falls back to serial uploads.

Every run also emits a cleaned, DSInternals-friendly `khdb-clean.txt` beside the shards so you can inspect or distribute the merged list before publishing.

When `-ForcePlainText` is specified the script automatically keeps a checkpoint (default: `<output>/khdb.checkpoint.json`) and resumes from it on the next run so massive inputs don’t restart from scratch. Use `-CheckpointPath` to relocate that file or `-NoCheckpoint` to disable the behavior entirely.
### Test Weak AD passwords
Run script Elysium.ps1 as an administrator and choose option 2 (Test Weak AD Passwords).
The script lists domains in the same order as they appear in `ElysiumSettings.txt`. After you pick one, it prompts for credentials and validates them against the selected domain controller before running the password-quality test.
The tool connects to the selected Domain Controller and compares accounts against KHDB (respecting the optional `CheckOnlyEnabledUsers` flag if configured). A timestamped text report is saved under `Reports`, and accounts with dictionary hits are also exported to a dedicated UPN-only text file to support follow-up automation.
The KHDB file is consumed by DSInternals as a sorted hash list with one NT hash per line (for example `HASH`). Do not include `:count` suffixes in `khdb.txt`; the packaging and update scripts normalize legacy `HASH:count` input to the hash-only format automatically.

#### Least privileges for password-quality testing
The DSInternals cmdlets (`Get-ADReplAccount`/`Test-PasswordQuality`) pull replicated password data, which requires DCSync-style rights. The account that runs option 2 does not have to be a Domain Admin if it has these permissions on the domain naming context:
- `Replicating Directory Changes`
- `Replicating Directory Changes All`
- `Replicating Directory Changes In Filtered Set` (needed on 2008 R2+ to read password hashes)

To delegate, enable Advanced Features in ADUC, right-click the domain, choose *Delegate Control…*, pick the service account, select *Create a custom task*, apply to *This object and all descendant objects*, and tick the three replication permissions above. Keep this account disabled and only activate it for scheduled tests.

#### Common errors
- `The server has rejected the client credentials.` or `Credentials ... were rejected`:
  The supplied username/password is invalid for the selected domain controller, or the session is not running in the expected domain context. Re-run and provide valid domain credentials.
- `Account '<user>' is missing the following replication permissions ...`:
  Starting with v2.2.0, the script pre-validates the three required replication extended rights against the domain object ACL before attempting DCSync. If this error appears, delegate the listed rights (see *Least privileges* above) and retry.
- `Get-ADReplAccount: Access is denied`:
  Credentials are valid, but the account does not have the three replication permissions listed above. This error should now be rare because the pre-check catches most permission issues early; if it still occurs, verify the account is not restricted by an additional conditional access or Group Policy setting.
- `Only FIPS certified cryptographic algorithms are enabled in .NET`:
  This warning comes from DSInternals under FIPS-enforced environments. Hash-quality operations that rely on MD5 may be limited.

#### Optional usage beacon
If you want to know the script was executed without collecting telemetry, set a pre-signed URL (for example, an S3 `PUT` URL) in `UsageBeaconUrl` inside `ElysiumSettings.txt`. When present, the weak-password script issues a single request as soon as it loads the settings. Only the script name, its version, a UTC timestamp, and the optional `UsageBeaconInstanceId` value are sent, and network failures never block the run. Choose the HTTP verb via `UsageBeaconMethod` (`GET`, `POST`, or `PUT`) and adjust the timeout with `UsageBeaconTimeoutSeconds` if your storage endpoint needs more time.

### Send current hashes for update KHDB
Run script Elysium.ps1 as an administrator and choose option 3 (Extract and Send Hashes).
Domains are listed in configuration order, after which the script prompts for the replication-capable account password. With valid credentials, it extracts current NTLM hashes (no history) for active accounts, compresses the results, encrypts them with the configured passphrase, and uploads the payload to the configured storage (Azure Blob or S3-compatible). A checksum-verified round-trip download confirms the upload before local artifacts are removed.

### Update Lithnet Password Protection store
Run script Elysium.ps1 as an administrator and choose option 5 (Update Lithnet Password Protection Store).
Configure the target folder via `LithnetStorePath` in `ElysiumSettings.txt` (the location created with `Open-Store`). The script automatically imports the `khdb.txt` file unless you override/add additional NTLM hash lists in `LithnetHashSources` (comma or semicolon separated). You can also populate plaintext password lists (`LithnetPlaintextSources`) and banned-word files (`LithnetBannedWordSources`), or enable `LithnetSyncHibp=true` to seed the store directly from the Have I Been Pwned API (using `Sync-HashesFromHibp`). Behind the scenes the helper loads the `LithnetPasswordProtection` module, opens the store, runs [`Import-CompromisedPasswordHashes`](https://docs.lithnet.io/password-protection/advanced-help/powershell-reference/import-compromisedpasswordhashes)/`Import-CompromisedPasswords`/`Import-BannedWords` for each configured file, and then closes the store.

S3-compatible usage notes:
- No AWS Tools required. The scripts sign requests using native SigV4 via .NET and HttpClient, including non-default endpoint ports.
- To force using AWS Tools instead, set `s3UseAwsTools = true` in `ElysiumSettings.txt` and install `AWS.Tools.S3`.
### Uninstallation
Run script Elysium.ps1 as an administrator and choose option 4 (Uninstall).
The script will then delete everything and remove the passphrase variable.
---
## FAQ

### What happens to the hashes we uploaded?
These hashes are subjected to cracking. Any cracked hash is then added to KHDB. Hash cracking happens on dedicated air-gapped machine and all sensitive material is never decrypted outside this machine. Secure exchange of decryption keys is arranged beforehand with every client.
### Do we need to upload the hashes?
Not at all. This step is purely optional, but it enables us to constantly improve the KHDB.
### What does "weak password" mean?
Account is flagged when it returns one or more of these conditions:
* Password hash is found in KHDB (that means it is known).
* Password is stored using reversible encryption.
* LM hashes are present.
* Has no password set.
* Has the same password as multiple other accounts.
* Has the SamAccountName as password.
* Is computer account with default password.
* Has Kerberos AES keys missing.
* Has not required Kerberos pre-authentication
* Only DES encryption is allowed to be used.
* Is susceptible to the Kerberoasting attack.
* Administrative accounts is allowed to be delegated to a service.
* Passwords of the account will never expire.
* Is not required to have a password.
* Requires smart card authentication and has a password.
### How are usernames paired with KHDB?
They are paired online while running the script. KHDB does not contain usernames as the extract script provides only hashes, not usernames. 
### Would our EDR solution interfere with this tool?
It should! If you have EDR installed on the host machine, this tool should be exceptioned.
### Would our monitoring tool detect this activity?
It should, as it is extremely sensitive operation that should never happen outside of this (or similar) procedure. Running this tool should be cleared with your SOC beforehand (or used as a test case).

---

## Weak password report
This section explains in detail individual parts of weak password report.

1. Reversible Encryption:
    * ****Explanation:**** Accounts have passwords stored in a reversible format that can be decrypted.
    * **Risk Assessment:** High. Decrypted passwords can be misused easily.
    * **Possible Cause:** Legacy applications requiring plaintext password equivalents.
    * **Use:** Compatibility with older applications.
    * **Remediation:** Disable reversible encryption through Group Policy ("Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy > Store passwords using reversible encryption").

2. LM Hashes Present:
   * **Explanation:** Use of outdated LAN Manager (LM) hashes for storing passwords.
   * **Risk Assessment:** Very High. LM hashes are easily cracked.
   * **Possible Cause:** Historical default settings for older Windows systems.
   * **Use:** Compatibility with legacy clients or systems.
   * **Remediation:** Disable LM hash storage via Group Policy ("Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change").

3. Accounts with No Password:
   * **Explanation:** Accounts are configured without a password.
   * **Risk Assessment:** Extremely High. Accounts are accessible without authentication.
   * **Possible Cause:** Oversight or initial setup convenience.
   * **Use:** Automated scripts or systems needing easy access.
   * **Remediation:** Ensure all accounts have strong passwords. Disable unnecessary accounts.

4. Passwords Found in Dictionary:
    * **Explanation:** Accounts use weak passwords found in common dictionaries.
    * **Risk Assessment:** High. Dictionary attacks can easily guess these passwords.
    * **Possible Cause:** Lack of strong password policies.
    * **Use:** User convenience and easy recall.
    * **Remediation:** Implement and enforce strong password policies, use password filter DLLs.


5. Same Passwords for Multiple Accounts:
    * **Explanation:** Multiple accounts share the same password.
    * **Risk Assessment:** High. Compromise of one account leads to multiple breaches.
    * **Possible Cause:** Administrative convenience.
    * **Use:** Simplified management across services.
    * **Remediation:** Establish unique passwords for each account, audit for password uniqueness.

6. SamAccountName as Password:
   * **Explanation:** Usernames are used as passwords.
   * **Risk Assessment:** High. Easy to guess and compromise.
   * **Possible Cause:** Rudimentary security setup.
   * **Use:** Lowering barriers for user access.
   * **Remediation:** Prohibit this practice through user education and strict password policies.

7. Computer Accounts with Default Passwords:
   * **Explanation:** Computer accounts use default passwords.
   * **Risk Assessment:** High. Default passwords are widely known.
   * **Possible Cause:** Incomplete setup or bulk deployments.
   * **Use:** Streamlined initial setup.
   * **Remediation:** Reset all default passwords to strong, unique ones.

8. Missing Kerberos AES Keys:
   * **Explanation:** Accounts lack AES keys for Kerberos, falling back to weaker encryption.
   * **Risk Assessment:** Moderate to High. Weakens Kerberos authentication.
   * **Possible Cause:** Incomplete updates or migrations.
   * **Use:** Compatibility with older systems.
   * **Remediation:** Enable AES encryption for Kerberos in account properties and domain policies.

9. No Kerberos Pre-Authentication Required:
   * **Explanation:** Accounts can request authentication data without pre-authentication.
   * **Risk Assessment:** High. Facilitates offline brute-force attacks.
   * **Possible Cause:** Troubleshooting or legacy system compatibility.
   * **Use:** Avoiding issues with older clients.
   * **Remediation:** Enable Kerberos pre-authentication for all accounts via account properties.

10. Only DES Encryption Allowed:
    * **Explanation:** Accounts are restricted to using DES encryption.
    * **Risk Assessment:** Very High. DES is weak and easily compromised.
    * **Possible Cause:** Retained settings from when DES was standard.
    * **Use:** Ensuring functionality of older applications.
    * **Remediation:** Configure accounts to use stronger encryption types like AES in Group Policy.

11. Susceptible to Kerberoasting:
    * **Explanation:** Service accounts have SPNs and weak passwords, making them vulnerable.
    * **Risk Assessment:** High. Enables offline password cracking.
    * **Possible Cause:** Lack of awareness about service account security.
    * **Use:** Service accounts needing elevated privileges.
    * **Remediation:** Implement strong password policies for service accounts, rotate passwords regularly, use Managed Service Accounts (MSA).

12. Administrative Accounts Allowed for Delegation:
    * **Explanation:** Admin accounts configured to allow delegation.
    * **Risk Assessment:** High. Can be misused to escalate privileges.
    * **Possible Cause:** Misunderstanding or overly permissive security culture.
    * **Use:** Facilitating administrative processes.
    * **Remediation:** Restrict delegation rights, use Constrained Delegation.

13. Passwords Will Never Expire:
    * **Explanation:** Accounts are configured to never require password changes.
    * **Risk Assessment:** Moderate to High. Increases risk of undetected breaches.
    * **Possible Cause:** Minimizing administrative burden.
    * **Use:** Reducing disruption from frequent password updates.
    * **Remediation:** Configure policies to require periodic password changes.

14. Accounts Not Required to Have a Password:
    * **Explanation:** Accounts do not require passwords for authentication.
    * **Risk Assessment:** Extremely High. Allows unrestricted access.
    * **Possible Cause:** Configuration error or setup for automated systems.
    * **Use:** Automating processes without manual authentication.
    * **Remediation:** Enforce password requirements for all accounts.

15. Smart Card Accounts with a Password:
    * **Explanation:** Smart card-required accounts also have passwords set.
    * **Risk Assessment:** Moderate to High. Bypasses smart card security.
    * **Possible Cause:** Hybrid authentication setup or legacy fallback.
    * **Use:** Providing a fallback in case of smart card issues.
    * **Remediation:** Require smart card for login, disable password fallback.
