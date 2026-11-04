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
* **Domain Credentials:** For weak-password testing (option 2), an account with the three replication rights (`Replicating Directory Changes`, `Replicating Directory Changes All`, `Replicating Directory Changes In Filtered Set`) on **both** the domain naming context **and** `CN=Configuration,DC=…` (which covers the schema NC via inheritance). Domain Admin also works but is not required. See *Least privileges* below for exact delegation steps. Keep this account disabled and enable only when running tests.
* **Network Requirements:** A stable connection to the domain controller in each tested AD domain and internet access (specific hostnames/IP addresses will be provided).

## Versioning and Releases

Elysium uses a **unified project version** starting with v2.2.0. The version is defined once, as `ModuleVersion` in `src/Elysium/Elysium.psd1`; the scripts read it from there at runtime (User-Agent, usage beacon, diagnostic dumps). To release, change `ModuleVersion`, add the `CHANGELOG.md` entry, commit, and tag `v<major>.<minor>.<patch>`.

Prior to v2.2.0, each script carried its own version number; those historical versions are preserved in the changelog for reference.

---
## Operation
### Install and update
This tool is provided in private git repository. Installation and updating is done with cloning and pulling from this repository.
During first run, the tool will ask for passphrase that will be used to encrypt/decrypt sensitive content.
After installation, edit ElysiumSettings.txt, check all variables and add domains to test.
The tool runs on Windows PowerShell 5.1 (always present on Windows) or PowerShell 7 (`pwsh`); KHDB downloads run concurrently on both. The two DSInternals-driven workflows (menu options 2 and 3, `Test-WeakADPasswords.ps1` and `Extract-NTHashes.ps1`) load the legacy `ActiveDirectory` and `DSInternals` modules, so they relaunch themselves under Windows PowerShell when started from pwsh.
### Update Known-Hashed Database (KHDB)
Run script Elysium.ps1 as an administrator and choose option 1 (Update Known-Hashes Database).
The updater pulls a manifest plus individual hash shards (two-hex prefix layout) from the configured storage (Azure Blob or S3-compatible), verifies each shard's size and SHA-256 against the manifest, replaces only changed shards, and rebuilds `khdb.txt` for local use. Shards no longer listed in the manifest are removed automatically. Up to `-MaxParallelTransfers` shards (default `5`) download concurrently on both Windows PowerShell 5.1 and PowerShell 7; override it when running the script directly (for example `.\Update-KHDB.ps1 -MaxParallelTransfers 8`). The KHDB credentials only need read access to the KHDB paths.

To publish an updated shard set (tool provider only), build the package with `tools/Prepare-KHDBStorage.ps1` and upload it with your storage provider's own CLI. The script runs on any OS with PowerShell 7 (`pwsh`) and needs no Elysium settings or credentials. It takes your sorted `khdb.txt` (or the directory/list of the Have I Been Pwned `.gz` slices), reconstructs the full 32-hex NTLM values (prefix + remainder), deduplicates, splits by the first two hex characters, and writes `manifest.json` (`version`, `shardPrefix`, and `sha256`/`size`/entry count per shard). Invalid or malformed entries are omitted and listed in `invalid-hashes.txt`.

```powershell
pwsh ./tools/Prepare-KHDBStorage.ps1 -SourcePath ./khdb.txt -OutputRoot ./publish -Force
```

Upload the shards first and `manifest.json` last, so a client never downloads a manifest that points at shards that are not there yet. The remote paths must match `-ShardRemotePrefix` (default `khdb/shards`, recorded in the manifest) and the clients' `KhdbManifestPath` (default `khdb/manifest.json`):

```sh
# S3-compatible, with the AWS CLI (rclone sync/copyto against an S3 remote works the same way)
aws s3 sync ./publish/shards s3://BUCKET/khdb/shards --endpoint-url https://s3.example.com
aws s3 cp   ./publish/manifest.json s3://BUCKET/khdb/manifest.json --endpoint-url https://s3.example.com

# Azure Blob Storage, with azcopy and a SAS that allows write
azcopy sync ./publish/shards "https://ACCOUNT.blob.core.windows.net/CONTAINER/khdb/shards?SAS"
azcopy copy ./publish/manifest.json "https://ACCOUNT.blob.core.windows.net/CONTAINER/khdb/manifest.json?SAS"
```

Shard names are stable (`00.txt` ... `ff.txt` with the default `-ShardSize 2`), so no remote deletion step is needed. Add `-ShowProgress` (optionally tune `-ProgressUpdateInterval`) for a running `Write-Progress` indicator while the hashes are being split. Pass `-ForcePlainText` when your `khdb.txt` already contains complete hashes and you want `.gz` references treated as invalid instead of being expanded.

Every run also emits a cleaned, DSInternals-friendly `khdb-clean.txt` beside the shards so you can inspect or distribute the merged list before publishing.

When `-ForcePlainText` is specified the script automatically keeps a checkpoint (default: `<output>/khdb.checkpoint.json`) and resumes from it on the next run so massive inputs don’t restart from scratch. Use `-CheckpointPath` to relocate that file or `-NoCheckpoint` to disable the behavior entirely.
### Test Weak AD passwords
Run script Elysium.ps1 as an administrator and choose option 2 (Test Weak AD Passwords).
The script lists domains in the same order as they appear in `ElysiumSettings.txt`. After you pick one, it prompts for credentials and validates them against the selected domain controller before running the password-quality test. To skip the domain prompt, name the domain: `.\Test-WeakADPasswords.ps1 -Domain contoso.local` (the same works for `.\Extract-NTHashes.ps1`). For fully non-interactive runs, call the cmdlets with a credential: `Import-Module .\src\Elysium; Test-ElysiumPasswordQuality -Domain contoso.local -Credential $cred` (or `Send-ElysiumHashExport`).
The tool connects to the selected Domain Controller and compares accounts against KHDB (respecting the optional `CheckOnlyEnabledUsers` flag if configured). A timestamped text report is saved under `Reports`, and accounts with dictionary hits are also exported to a dedicated UPN-only text file to support follow-up automation. Next to the text report, a `.json` file holds the same results as data: one finding per check (`WeakPassword`, `LMHash`, `DuplicatePasswordGroups`, ...) with each account's logon name and UPN, plus domain, DC, tool version and the number of accounts tested. The cmdlet also returns a summary object (domain, accounts tested, finding counts per check, report paths).
The KHDB file is consumed by DSInternals as a sorted hash list with one NT hash per line (for example `HASH`). Do not include `:count` suffixes in `khdb.txt`; the packaging and update scripts normalize legacy `HASH:count` input to the hash-only format automatically.

#### Least privileges for password-quality testing
The DSInternals cmdlets (`Get-ADReplAccount`/`Test-PasswordQuality`) pull replicated password data using the MS-DRSR (DCSync) protocol. The account does not need to be a Domain Admin; delegate these three extended rights on **two** AD objects:

| Object | Why |
|--------|-----|
| Domain NC root — e.g. `DC=admin,DC=lan` | Required to replicate account password hashes |
| Configuration NC root — e.g. `CN=Configuration,DC=admin,DC=lan` | Required by DSInternals 7.0+ to fetch the AD schema via DRS before replication; covers the schema NC (`CN=Schema,CN=Configuration,DC=…`) via inheritance |

Rights to delegate on both objects:
- `Replicating Directory Changes`
- `Replicating Directory Changes All`
- `Replicating Directory Changes In Filtered Set` (required on 2008 R2+ to read password hashes)

**To delegate in ADUC:** enable *Advanced Features*, right-click each object above, choose *Properties* > *Security* > *Advanced* > *Add*, select the service account, set *Applies to: This object only*, and tick the three rights. Repeat for both objects.

**To delegate via `dsacls`** (replace `DC=admin,DC=lan` and `DOMAIN\svc` as appropriate):
```powershell
foreach ($nc in @('DC=admin,DC=lan', 'CN=Configuration,DC=admin,DC=lan')) {
    dsacls $nc /I:T /G "DOMAIN\svc:CA;Replicating Directory Changes"
    dsacls $nc /I:T /G "DOMAIN\svc:CA;Replicating Directory Changes All"
    dsacls $nc /I:T /G "DOMAIN\svc:CA;Replicating Directory Changes In Filtered Set"
}
```

Keep the service account disabled and only activate it for scheduled tests.

#### Common errors
- `The server has rejected the client credentials.` or `Credentials ... were rejected`:
  The supplied username/password is invalid for the selected domain controller, or the session is not running in the expected domain context. Re-run and provide valid domain credentials.
- `Account '<user>' is missing the following replication permissions ...`:
  Starting with v2.2.0, the script pre-validates the three required replication extended rights against the domain object ACL before attempting DCSync. If this error appears, delegate the listed rights (see *Least privileges* above) and retry.
- `Account '<user>' failed replication permission check ... (DENIED by explicit Deny ACE for '<sid>')`:
  The pre-flight check (v2.4.5+) also scans for explicit **Deny** ACEs on the replication extended rights, not just missing Allow grants. A Deny ACE — commonly added by hardening baselines that Deny a broad group (`Everyone`, `Domain Users`, `Authenticated Users`) the replication rights and Allow only named DCSync accounts — wins over any Allow, even one granted directly to this account. Open *Advanced Security* on the flagged NC object, find the Deny entry that matches this account or one of its groups, and either remove it or exclude the service account/its group from it.
- `Replication access was denied` (from `Get-ADReplAccount`) **after the pre-flight check reported success**:
  This means the ACL looks correct from LDAP but the live DRS (`GetNCChanges`) call still denies access. Known causes, roughly in likelihood order:
  1. **Target DC is an RODC.** Read-only domain controllers enforce the Password Replication Policy and will refuse to originate a full DCSync of secrets for accounts outside their allowed replication list, regardless of ACL grants. Point `ElysiumSettings.txt` at a writable DC instead.
  2. **ACL change hasn't converged yet.** If the rights were just delegated on a different DC than the one configured for the test, wait for AD replication to catch up (or force it with `repadmin /syncall`) before retrying.
  3. **Explicit Deny ACE not caught by an older script version.** Update to v2.4.5+ so the pre-flight check surfaces it (see above) instead of only discovering it at DCSync time.
  4. **Account is in a cross-domain group** whose scope isn't visible in `tokenGroups` from the DC being queried (for example, a domain-local group in a different domain). Re-delegate directly to the account or to a universal group instead.

  For a definitive answer straight from the DC: enable "Audit Directory Service Access" and add a SACL for `Replicating Directory Changes*` on the domain/schema NC, then check the DC's Security event log for Event ID 4662 on the next failed run — it names the exact object and right that were denied.
- `Only FIPS certified cryptographic algorithms are enabled in .NET`:
  This warning comes from DSInternals under FIPS-enforced environments. Hash-quality operations that rely on MD5 may be limited.

#### Optional usage beacon
If you want to know the script was executed without collecting telemetry, set a pre-signed URL (for example, an S3 `PUT` URL) in `UsageBeaconUrl` inside `ElysiumSettings.txt`. When present, the weak-password script issues a single request as soon as it loads the settings. Only the script name, its version, a UTC timestamp, and the optional `UsageBeaconInstanceId` value are sent, and network failures never block the run. Choose the HTTP verb via `UsageBeaconMethod` (`GET`, `POST`, or `PUT`) and adjust the timeout with `UsageBeaconTimeoutSeconds` if your storage endpoint needs more time.

### Send current hashes for update KHDB
Run script Elysium.ps1 as an administrator and choose option 3 (Extract and Send Hashes).
Domains are listed in configuration order, after which the script prompts for the replication-capable account password. With valid credentials, it extracts current NTLM hashes (no history) for active accounts, compresses the results, encrypts them with the configured passphrase, and uploads the payload to the configured storage (Azure Blob or S3-compatible). The upload is a single PUT that the storage service checks against a digest sent with it (`Content-MD5` on Azure, the SigV4-signed SHA-256 on S3) and rejects if the body does not match, so nothing is downloaded back: the upload credentials need write access only, and should not be able to read or list other uploads.

**Encrypted export format (v2.4.6+, magic `ELY2`):** `4-byte magic 'ELY2' | 16-byte PBKDF2 salt | 16-byte AES IV | AES-256-CBC ciphertext | 32-byte HMAC-SHA256`. Both keys are derived from the configured passphrase via one PBKDF2-SHA256 (100,000 iterations) byte stream: the first 32 bytes are the AES key, the next 32 are the HMAC key. The HMAC covers `magic | salt | iv | ciphertext` (encrypt-then-MAC) so a decrypt tool must verify it *before* decrypting - CBC alone doesn't detect a wrong passphrase or corrupted/tampered ciphertext, it just produces garbage or an unhelpful padding exception. This is a breaking change from the older `ELY1` format (no HMAC trailer) produced before v2.4.6; any external decryption tooling on the air-gapped cracking machine needs updating to match. The bundled `tools/decrypt.py` reads `ELY2`, `ELY1`, and the pre-`ELY1` legacy format; `python3 tests/test_decrypt.py` checks it against the PowerShell encryptor (needs `pwsh` and `pycryptodome`).

### Update Lithnet Password Protection store
Run script Elysium.ps1 as an administrator and choose option 4 (Update Lithnet Password Protection Store).
Configure the target folder via `LithnetStorePath` in `ElysiumSettings.txt` (the location created with `Open-Store`). The script automatically imports the KHDB (`WeakPasswordsDatabase` under `InstallationPath`, default `khdb.txt` next to the scripts) unless you override/add additional NTLM hash lists in `LithnetHashSources` (comma or semicolon separated). You can also populate plaintext password lists (`LithnetPlaintextSources`) and banned-word files (`LithnetBannedWordSources`), or enable `LithnetSyncHibp=true` to seed the store directly from the Have I Been Pwned API (using `Sync-HashesFromHibp`). Behind the scenes the helper loads the `LithnetPasswordProtection` module, opens the store, runs [`Import-CompromisedPasswordHashes`](https://docs.lithnet.io/password-protection/advanced-help/powershell-reference/import-compromisedpasswordhashes)/`Import-CompromisedPasswords`/`Import-BannedWords` for each configured file, and then closes the store.

S3-compatible usage notes:
- No AWS Tools or Az modules required. Requests are signed with native SigV4 (S3) or use the SAS token (Azure) via .NET HttpClient, including non-default endpoint ports.
### Uninstallation
Run script Elysium.ps1 as an administrator and choose option 5 (Uninstall).
After you type `YES` to confirm, the script deletes everything (including reports, the KHDB, and settings) and removes the passphrase variable. Run `.\Uninstall.ps1 -Force` to skip the confirmation.
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
