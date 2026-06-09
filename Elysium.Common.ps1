$script:ElysiumVersion = '2.2.2'

function Invoke-RestartWithExecutable {
    param(
        [string]$ExecutablePath,
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if (-not $ExecutablePath) { return }
    if (-not $PSCommandPath) { return }

    $argList = @('-NoLogo', '-NoProfile', '-File', $PSCommandPath)

    if ($BoundParameters) {
        foreach ($entry in $BoundParameters.GetEnumerator()) {
            $key = "-$($entry.Key)"
            $value = $entry.Value
            if ($value -is [System.Management.Automation.SwitchParameter]) {
                if ($value.IsPresent) { $argList += $key }
            } else {
                $argList += $key
                $argList += $value
            }
        }
    }

    if ($UnboundArguments) {
        $argList += $UnboundArguments
    }

    & $ExecutablePath @argList
    exit $LASTEXITCODE
}

function Restart-WithPwshIfAvailable {
    param(
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if ($PSVersionTable.PSVersion.Major -ge 7 -or $PSVersionTable.PSEdition -eq 'Core') { return }
    $pwsh = Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue
    if (-not $pwsh) { return }
    Write-Host ("PowerShell 7 detected at '{0}'; relaunching script under pwsh..." -f $pwsh.Path)
    Invoke-RestartWithExecutable -ExecutablePath $pwsh.Path -BoundParameters $BoundParameters -UnboundArguments $UnboundArguments
}

function Restart-WithWindowsPowerShellIfAvailable {
    param(
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') { return }
    $powershellCmd = Get-Command -Name 'powershell.exe' -ErrorAction SilentlyContinue
    $powershellPath = $null
    if ($powershellCmd) {
        $powershellPath = $powershellCmd.Path
    } else {
        $defaultPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $defaultPath) {
            $powershellPath = $defaultPath
        }
    }
    if (-not $powershellPath) {
        Write-Warning 'Windows PowerShell (powershell.exe) was not found; continuing under current host.'
        return
    }
    Write-Host ("Windows PowerShell detected at '{0}'; relaunching script under powershell.exe..." -f $powershellPath)
    Invoke-RestartWithExecutable -ExecutablePath $powershellPath -BoundParameters $BoundParameters -UnboundArguments $UnboundArguments
}

# ---------------------------------------------------------------------------
# Settings loading
# ---------------------------------------------------------------------------

function Read-KeyValueSettingsFile {
    param([Parameter(Mandatory)][string]$Path)
    $result = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($null -eq $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith('#')) { continue }
        $kv = $line -split '=', 2
        if ($kv.Count -ne 2) { continue }
        $key = $kv[0].Trim()
        $value = $kv[1].Trim()
        if (-not $key) { continue }
        if ($value.StartsWith("'") -and $value.EndsWith("'") -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $result[$key] = $value
    }
    return $result
}

function Read-ElysiumSettings {
    param([Parameter(Mandatory)][string]$ScriptRoot)
    $settingsPath = Join-Path -Path $ScriptRoot -ChildPath 'ElysiumSettings.txt'
    if (-not (Test-Path -LiteralPath $settingsPath)) {
        throw "Settings file not found at $settingsPath"
    }
    return Read-KeyValueSettingsFile -Path $settingsPath
}

function Get-SettingsValue {
    param(
        [hashtable]$Settings,
        [string]$Key
    )
    if (-not $Settings) { return $null }
    if ($Settings.ContainsKey($Key)) { return $Settings[$Key] }
    return $null
}

# ---------------------------------------------------------------------------
# Parallel execution helpers
# ---------------------------------------------------------------------------

function Get-FunctionDefinitionText {
    param([Parameter(Mandatory)][string]$Name)
    $cmd = Get-Command -Name $Name -CommandType Function -ErrorAction Stop
    return $cmd.ScriptBlock.Ast.Extent.Text
}

# ---------------------------------------------------------------------------
# Azure Blob Storage helpers
# ---------------------------------------------------------------------------

function Build-BlobUri {
    param(
        [string]$Account,
        [string]$Container,
        [string]$Sas,
        [string]$BlobName
    )

    if ([string]::IsNullOrWhiteSpace($Account)) { throw 'storageAccountName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($Container)) { throw 'containerName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($Sas)) { throw 'sasToken is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($BlobName)) { throw 'BlobName cannot be empty.' }

    $sas = $Sas.Trim()
    if (-not $sas.StartsWith('?')) { $sas = '?' + $sas }
    $normalizedBlob = $BlobName.Replace('\', '/').TrimStart('/')
    $builder = [System.UriBuilder]::new("https://$Account.blob.core.windows.net/$Container/$normalizedBlob")
    $builder.Query = $sas.TrimStart('?')
    return $builder.Uri.AbsoluteUri
}

# ---------------------------------------------------------------------------
# Storage path utilities
# ---------------------------------------------------------------------------

function Combine-StoragePath {
    param(
        [string]$Prefix,
        [string]$Name
    )

    $cleanName = $Name.Replace('\', '/').TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($Prefix)) { return $cleanName }
    $normalizedPrefix = $Prefix.Replace('\', '/').Trim('/')
    if ([string]::IsNullOrEmpty($normalizedPrefix)) { return $cleanName }
    return "$normalizedPrefix/$cleanName"
}

# ---------------------------------------------------------------------------
# AWS SigV4 / S3 helpers
# ---------------------------------------------------------------------------

function Get-Bytes([string]$s) { return [System.Text.Encoding]::UTF8.GetBytes($s) }

function Get-HashHex([byte[]]$bytes) {
    if ($null -eq $bytes) { $bytes = [byte[]]@() }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $ms = New-Object System.IO.MemoryStream -ArgumentList (,$bytes)
        try {
            $hash = $sha.ComputeHash([System.IO.Stream]$ms)
        } finally { $ms.Dispose() }
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function HmacSha256([byte[]]$key, [string]$data) {
    $h = [System.Security.Cryptography.HMACSHA256]::new($key)
    try {
        $b = [System.Text.Encoding]::UTF8.GetBytes($data)
        $ms = New-Object System.IO.MemoryStream -ArgumentList (,$b)
        try {
            return $h.ComputeHash([System.IO.Stream]$ms)
        } finally { $ms.Dispose() }
    } finally { $h.Dispose() }
}

function GetSignatureKey([string]$secret, [string]$dateStamp, [string]$regionName, [string]$serviceName) {
    $kDate = HmacSha256 (Get-Bytes ('AWS4' + $secret)) $dateStamp
    $kRegion = HmacSha256 $kDate $regionName
    $kService = HmacSha256 $kRegion $serviceName
    HmacSha256 $kService 'aws4_request'
}

function UriEncode([string]$data, [bool]$encodeSlash) {
    if ($null -eq $data) { return '' }
    $enc = [System.Uri]::EscapeDataString($data)
    if (-not $encodeSlash) { $enc = $enc -replace '%2F', '/' }
    return $enc
}

function BuildCanonicalPath([System.Uri]$uri) {
    $segments = $uri.AbsolutePath.Split('/')
    $encoded = @()
    foreach ($s in $segments) { $encoded += (UriEncode $s $false) }
    $path = ($encoded -join '/')
    if (-not $path.StartsWith('/')) { $path = '/' + $path }
    return $path
}

function ToHex([byte[]]$b) { ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant() }

function BuildAuthHeaders($method, [System.Uri]$uri, [string]$region, [string]$accessKey, [string]$secretKey, [string]$payloadHash) {
    $algorithm = 'AWS4-HMAC-SHA256'
    $timestamp = (Get-Date).ToUniversalTime()
    $amzDate = $timestamp.ToString('yyyyMMddTHHmmssZ')
    $dateStamp = $timestamp.ToString('yyyyMMdd')
    $hostHeader = $uri.Host
    if (-not $uri.IsDefaultPort) { $hostHeader = "${hostHeader}:$($uri.Port)" }
    $canonicalUri = BuildCanonicalPath $uri
    $canonicalQueryString = ''
    $canonicalHeaders = "host:$hostHeader`n" + "x-amz-content-sha256:$payloadHash`n" + "x-amz-date:$amzDate`n"
    $signedHeaders = 'host;x-amz-content-sha256;x-amz-date'
    $canonicalRequest = "$method`n$canonicalUri`n$canonicalQueryString`n$canonicalHeaders`n$signedHeaders`n$payloadHash"
    $credentialScope = "$dateStamp/$region/s3/aws4_request"
    $stringToSign = "$algorithm`n$amzDate`n$credentialScope`n$((Get-HashHex (Get-Bytes $canonicalRequest)))"
    $signingKey = GetSignatureKey $secretKey $dateStamp $region 's3'
    $signature = ToHex (HmacSha256 $signingKey $stringToSign)
    $authHeader = "$algorithm Credential=$accessKey/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"
    @{
        'x-amz-date'           = $amzDate
        'x-amz-content-sha256' = $payloadHash
        'Authorization'        = $authHeader
    }
}

function BuildS3Uri([string]$endpointUrl, [string]$bucket, [string]$key, [bool]$forcePathStyle) {
    $base = [System.Uri]$endpointUrl
    $builder = [System.UriBuilder]::new($base)
    $normalizedKey = $key.Replace('\', '/').TrimStart('/')
    if ($forcePathStyle) {
        $path = $builder.Path.TrimEnd('/')
        if ([string]::IsNullOrEmpty($path)) { $path = '/' }
        $builder.Path = ($path.TrimEnd('/') + '/' + $bucket + '/' + $normalizedKey)
    } else {
        $builder.Host = "$bucket." + $builder.Host
        $path = $builder.Path.TrimEnd('/')
        if ([string]::IsNullOrEmpty($path)) { $path = '/' }
        $builder.Path = ($path.TrimEnd('/') + '/' + $normalizedKey)
    }
    return $builder.Uri
}

function Ensure-AWSS3Module {
    try { $null = [Amazon.S3.AmazonS3Client]; return } catch {}
    try { Import-Module -Name AWS.Tools.S3 -ErrorAction Stop; return } catch {}
    try { Import-Module -Name AWSPowerShell.NetCore -ErrorAction Stop; return } catch {}
    throw "AWS Tools for PowerShell not found. Install with: Install-Module AWS.Tools.S3 -Scope CurrentUser"
}

function New-S3Client {
    param(
        [string]$EndpointUrl,
        [string]$Region,
        [string]$AccessKeyId,
        [string]$SecretAccessKey,
        [bool]$ForcePathStyle = $true
    )
    Ensure-AWSS3Module
    $creds = New-Object Amazon.Runtime.BasicAWSCredentials($AccessKeyId, $SecretAccessKey)
    $cfg = New-Object Amazon.S3.AmazonS3Config
    if ($EndpointUrl) { $cfg.ServiceURL = $EndpointUrl }
    if ($Region) { try { $cfg.RegionEndpoint = [Amazon.RegionEndpoint]::GetBySystemName($Region) } catch {} }
    $cfg.ForcePathStyle = [bool]$ForcePathStyle
    return (New-Object Amazon.S3.AmazonS3Client($creds, $cfg))
}

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

    $requiredRights = [ordered]@{
        'Replicating Directory Changes'                 = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'Replicating Directory Changes All'             = [guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        'Replicating Directory Changes In Filtered Set' = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
    }

    $callerSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $samName = $Credential.UserName -replace '^.*\\', ''
        $adUser = Get-ADUser -Identity $samName -Server $Server -Credential $Credential `
            -Properties SID, DistinguishedName -ErrorAction Stop
        [void]$callerSids.Add($adUser.SID.Value)

        # tokenGroups is a constructed attribute containing all SIDs in the user's token,
        # including nested group memberships — more reliable than walking MemberOf recursively
        $userDe = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$Server/$($adUser.DistinguishedName)",
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
        $userDe.RefreshCache(@('tokenGroups'))
        foreach ($sidBytes in $userDe.Properties['tokenGroups']) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
            [void]$callerSids.Add($sid.Value)
        }
    } catch {
        Write-Warning ("Could not resolve account SIDs for replication permission pre-check: {0}. Skipping." -f $_.Exception.Message)
        return
    }

    $acl = $null
    try {
        $de = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$Server/$DomainDN",
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
        $acl = $de.ObjectSecurity.GetAccessRules(
            $true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
        Write-Warning ("Could not read domain object ACL for replication permission pre-check: {0}. Skipping." -f $_.Exception.Message)
        return
    }

    $missing = @()
    foreach ($rightName in $requiredRights.Keys) {
        $guid    = $requiredRights[$rightName]
        $granted = $false
        foreach ($ace in $acl) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (-not ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) { continue }
            if ($ace.ObjectType -ne $guid) { continue }
            if ($callerSids.Contains($ace.IdentityReference.Value)) { $granted = $true; break }
        }
        if (-not $granted) { $missing += $rightName }
    }

    if ($missing.Count -gt 0) {
        throw ("Account '{0}' is missing the following replication permissions on '{1}':`n  - {2}`n`nGrant these extended rights on the domain object to allow DCSync-based hash retrieval." -f `
            $Credential.UserName, $DomainDN, ($missing -join "`n  - "))
    }

    Write-Host ("[+] Replication permissions verified for '{0}'." -f $Credential.UserName)
}
