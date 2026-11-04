# ---------------------------------------------------------------------------
# Active Directory credential and permission helpers
# (requires the ActiveDirectory module to be loaded before calling)
# ---------------------------------------------------------------------------

function Get-ValidatedADCredential {
    param (
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$Server,
        [int]$MaxAttempts = 3
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $credential = Get-Credential -Message "Enter AD credentials with replication rights for $DomainName (attempt $attempt/$MaxAttempts)"
        if ($null -eq $credential) {
            throw "Credential prompt was cancelled."
        }

        try {
            Get-ADDomain -Server $Server -Credential $credential -ErrorAction Stop | Out-Null
            Write-Verbose ("Credential pre-check succeeded for '{0}' against '{1}'." -f $credential.UserName, $Server)
            return $credential
        } catch {
            $message = $_.Exception.Message
            if ($message -match 'rejected the client credentials|unknown user name|bad password|logon failure') {
                Write-Warning ("Credentials were rejected for '{0}' (attempt {1}/{2})." -f $credential.UserName, $attempt, $MaxAttempts)
                if ($attempt -lt $MaxAttempts) { continue }
                throw "Credentials were rejected by domain controller '$Server' after $MaxAttempts attempts."
            }
            throw "Credential pre-check failed against '$Server': $message"
        }
    }
}

function Test-ReplicationPermissions {
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )

    $allThreeRights = [ordered]@{
        'Replicating Directory Changes'                 = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'Replicating Directory Changes All'             = [guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        'Replicating Directory Changes In Filtered Set' = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
    }

    # DSInternals 7.0 fetches the AD schema via DRS (GetNCChanges) before replicating accounts.
    # The schema NC has its own ACL - rights on the domain NC do not cover it.
    # Older DSInternals read schema via LDAP (no special rights needed); v7.0 switched to DRS.
    $schemaDN = "CN=Schema,CN=Configuration,$DomainDN"

    $ncsToCheck = [ordered]@{
        $DomainDN = $allThreeRights
        $schemaDN = [ordered]@{
            'Replicating Directory Changes' = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        }
    }

    $callerSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        # Get-ADUser -Identity accepts a DN, GUID, SID, or sAMAccountName - but NOT a UPN. A
        # UPN-formatted credential (user@domain.tld) has no backslash, so naively stripping a
        # 'DOMAIN\' prefix left the full UPN in place, -Identity threw, and this whole pre-check
        # was silently skipped (caught below) regardless of how the username was typed.
        $rawUserName = $Credential.UserName
        if ($rawUserName -match '^[^\\]+\\(.+)$') {
            $adUser = Get-ADUser -Identity $Matches[1] -Server $Server -Credential $Credential `
                -Properties SID, DistinguishedName, adminCount -ErrorAction Stop
        } elseif ($rawUserName -match '@') {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$rawUserName'" -Server $Server -Credential $Credential `
                -Properties SID, DistinguishedName, adminCount -ErrorAction Stop | Select-Object -First 1
            if (-not $adUser) { throw "No AD user found with UserPrincipalName '$rawUserName'." }
        } else {
            $adUser = Get-ADUser -Identity $rawUserName -Server $Server -Credential $Credential `
                -Properties SID, DistinguishedName, adminCount -ErrorAction Stop
        }
        [void]$callerSids.Add($adUser.SID.Value)

        # tokenGroups is a constructed attribute containing all SIDs in the user's token,
        # including nested group memberships - more reliable than walking MemberOf recursively.
        # Look up by DistinguishedName (unambiguous) rather than re-deriving the username format.
        $adUserWithTokenGroups = Get-ADUser -Identity $adUser.DistinguishedName -Server $Server -Credential $Credential `
            -Properties tokenGroups -ErrorAction Stop
        foreach ($sidBytes in $adUserWithTokenGroups.tokenGroups) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier(@([byte[]]$sidBytes), 0)
            [void]$callerSids.Add($sid.Value)
        }

        # adminCount=1 means SDProp is managing this account; it runs every 60 min and can
        # silently revert replication rights or group memberships granted to the account
        if ($adUser.adminCount -eq 1) {
            Write-Warning ("Account '{0}' has adminCount=1 (SDProp-protected). It is or was a member of a privileged group. SDProp runs every 60 minutes and may silently revert replication rights or group memberships on this account." -f $Credential.UserName)
        }

        # Protected Users group (RID 525) blocks the Kerberos mechanisms DSInternals uses for DRS
        $domainSidStr = $adUser.SID.Value.Substring(0, $adUser.SID.Value.LastIndexOf('-'))
        $protectedUsersSid = "$domainSidStr-525"
        if ($callerSids.Contains($protectedUsersSid)) {
            Write-Warning ("Account '{0}' is a member of Protected Users. This group restricts Kerberos delegation and RC4 authentication that DSInternals requires for DRS replication - access will be denied regardless of assigned rights." -f $Credential.UserName)
        }
    } catch {
        Write-Warning ("Could not resolve account SIDs for replication permission pre-check: {0}. Skipping." -f $_.Exception.Message)
        return
    }

    $allMissingLines = @()

    foreach ($ncEntry in $ncsToCheck.GetEnumerator()) {
        $ncDN         = $ncEntry.Key
        $rightsToCheck = $ncEntry.Value

        $acl = $null
        $de = $null
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$Server/$ncDN",
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
            $acl = $de.ObjectSecurity.GetAccessRules(
                $true, $true, [System.Security.Principal.SecurityIdentifier])
        } catch {
            Write-Warning ("Could not read ACL on '$ncDN' for replication permission pre-check: {0}. Skipping." -f $_.Exception.Message)
            continue
        } finally {
            if ($de) { $de.Dispose() }
        }

        foreach ($rightName in $rightsToCheck.Keys) {
            $guid             = $rightsToCheck[$rightName]
            $granted          = $false
            $aceExistsForGuid = $false
            $denyIdentity     = $null
            foreach ($ace in $acl) {
                # InheritOnly ACEs apply to child objects only - the NC root itself is not covered
                if ([bool]($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
                $rights        = $ace.ActiveDirectoryRights
                $hasExtended   = [bool]($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
                $hasGenericAll = [bool]($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
                # Match: exact GUID, OR ExtendedRight with empty ObjectType (all extended rights), OR GenericAll
                $isMatch = $hasGenericAll `
                    -or ($hasExtended -and $ace.ObjectType -eq [guid]::Empty) `
                    -or ($hasExtended -and $ace.ObjectType -eq $guid)
                if (-not $isMatch) { continue }
                if (-not $callerSids.Contains($ace.IdentityReference.Value)) { continue }

                if ($ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                    # Explicit Deny ACEs are evaluated before Allow ACEs in a canonical ACL and win
                    # regardless of any Allow found elsewhere. A check that only scans Allow ACEs would
                    # falsely report the right as granted while the actual DRS call is still denied.
                    $denyIdentity = $ace.IdentityReference.Value
                    continue
                }

                if ($ace.ObjectType -eq $guid) { $aceExistsForGuid = $true }
                $granted = $true
            }
            if ($denyIdentity) {
                $allMissingLines += "[on $ncDN] $rightName (DENIED by explicit Deny ACE for '$denyIdentity' - this overrides any Allow grant)"
            } elseif (-not $granted) {
                $hint = if ($aceExistsForGuid) {
                    ' (ACE exists but not assigned to this account or any of its groups)'
                } else {
                    ' (no ACE found for this right on this object)'
                }
                $allMissingLines += "[on $ncDN] $rightName$hint"
            }
        }
    }

    if ($allMissingLines.Count -gt 0) {
        $schemaNote = ''
        if ($allMissingLines | Where-Object { $_ -match [regex]::Escape($schemaDN) }) {
            $schemaNote = ("`n`nNOTE: DSInternals 7.0 fetches the AD schema via DRS before replicating accounts." +
                " Grant 'Replicating Directory Changes' on CN=Configuration,$DomainDN" +
                " (covers Schema NC via inheritance) in addition to the domain NC rights.")
        }
        $denyNote = ''
        if ($allMissingLines | Where-Object { $_ -match 'DENIED by explicit Deny ACE' }) {
            $denyNote = ("`n`nNOTE: at least one right is blocked by an explicit Deny ACE, not a missing grant." +
                " Find and remove/scope it: Advanced Security on the NC object > look for a Deny entry" +
                " covering 'Replicating Directory Changes*' that matches this account or one of its groups" +
                " (common with hardening baselines that Deny a broad group like Everyone/Domain Users).")
        }
        throw ("Account '{0}' failed replication permission check:`n  - {1}{2}{3}" -f `
            $Credential.UserName, ($allMissingLines -join "`n  - "), $schemaNote, $denyNote)
    }

    Write-Host ("[+] Replication permissions verified for '{0}' on domain NC and schema NC." -f $Credential.UserName)
}

function Test-DCClockSkew {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )
    $rootDse = $null
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$Server/RootDSE",
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
        $dcTimeStr = $rootDse.Properties['currentTime'][0]
        $dcTime = [datetime]::ParseExact(
            $dcTimeStr, 'yyyyMMddHHmmss.0Z',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
        $skewSeconds = [Math]::Abs(([datetime]::UtcNow - $dcTime).TotalSeconds)
        if ($skewSeconds -gt 300) {
            Write-Warning ("Clock skew of {0:N0}s with '{1}' exceeds Kerberos limit of 300s - authentication will fail. Sync the clock: w32tm /resync /force" -f $skewSeconds, $Server)
        } elseif ($skewSeconds -gt 60) {
            Write-Warning ("Clock skew of {0:N0}s detected with '{1}'. Kerberos allows up to 300s - approaching the limit." -f $skewSeconds, $Server)
        } else {
            Write-Host ("[+] Clock skew with '{0}': {1:N0}s (OK)." -f $Server, $skewSeconds)
        }
    } catch {
        Write-Warning ("Could not check clock skew against '{0}': {1}" -f $Server, $_.Exception.Message)
    } finally {
        if ($rootDse) { $rootDse.Dispose() }
    }
}
