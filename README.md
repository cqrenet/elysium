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
* **Domain Credentials:** A domain user account with Domain Admin privileges for each tested AD domain. This account should be active only during testing.
* **Network Requirements:** A stable connection to the domain controller in each tested AD domain and internet access (specific hostnames/IP addresses will be provided).
---
## Operation
### Install and update
This tool is provided in private git repository. Installation and updating is done with cloning and pulling from this repository.
During first run, the tool will ask for passphrase that will be used to encrypt/decrypt sensitive content.
After installation, edit ElysiumSettings.txt, check all variables and add domains to test.
### Update Known-Hashed Database (KHDB)
Run script Elysium.ps1 as an administrator and choose option 1 (Update Known-Hashes Database).
The script downloads the database from the configured storage (Azure Blob or S3-compatible), decompresses it and updates the current database.
### Test Weak AD passwords
Run script Elysium.ps1 as an administrator and choose option 2 (Test Weak AD Passwords).
The script will then ask for the domain to be tested and upon choice will ask for domain administrator password. The DA username is already provided in the script for each domain.
The tool then connects to Domain Controller and tests all enabled users in the domain against KHDB. PDF report with findings is then generated.
### Send current hashes for update KHDB
Run script Elysium.ps1 as an administrator and choose option 3 (Extract and Send Hashes).
The tool will then ask for domain and password of domain administrator. With correct credentials, the tool will then extract current hashes (no history) of non-disabled users, compresses and encrypts them and uploads them to the configured storage (Azure Blob or S3-compatible) for pickup by the tool provider.

S3-compatible usage notes:
- No AWS Tools required. The scripts can sign requests using native SigV4 via .NET and HttpClient.
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
