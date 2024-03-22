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
The script will then download the database from dedicated Azure Storage, decompresses it and updates the current database.
### Test Weak AD passwords
Run script Elysium.ps1 as an administrator and choose option 2 (Test Weak AD Passwords).
The script will then ask for the domain to be tested and upon choice will ask for domain administrator password. The DA username is already provided in the script for each domain.
The tool then connects to Domain Controller and tests all enabled users in the domain against KHDB. PDF report with findings is then generated.
### Send current hashes for update KHDB
Run script Elysium.ps1 as an administrator and choose option 3 (Extract and Send Hashes).
The tool will then ask for domain and password of domain administrator. With correct credentials, the tool will then extract current hashes (no history) of non-disabled users, compresses and encrypts them and sends them to the tool provider.
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