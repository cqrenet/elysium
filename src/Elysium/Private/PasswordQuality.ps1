# DSInternals / ActiveDirectory password-quality helpers used by Test-ElysiumPasswordQuality.
# ponytail: several of these read variables that Test-ElysiumPasswordQuality sets ($runningInPSCore,
# $onWindows, $reportPathBase, $timestamp, $header, $footer) through PowerShell's dynamic scoping,
# exactly as they read the script-level variables before the move. Anything else calling them must
# set those first; they become parameters when the cmdlet gets non-interactive parameters.

function Invoke-UsageBeacon {
    param(
        [string]$Url,
        [string]$Method = 'GET',
        [int]$TimeoutSeconds = 5,
        [string]$InstanceId
    )

    if ([string]::IsNullOrWhiteSpace($Url)) { return }

    $normalizedMethod = 'GET'
    if (-not [string]::IsNullOrWhiteSpace($Method)) {
        $normalizedMethod = $Method.ToUpperInvariant()
    }
    if ($normalizedMethod -notin @('GET', 'POST', 'PUT')) {
        $normalizedMethod = 'GET'
    }

    $requestParams = @{
        Uri         = $Url
        Method      = $normalizedMethod
        ErrorAction = 'Stop'
    }

    $invokeWebRequestCmd = $null
    try { $invokeWebRequestCmd = Get-Command -Name Invoke-WebRequest -ErrorAction Stop } catch { }
    if ($invokeWebRequestCmd -and $invokeWebRequestCmd.Parameters.ContainsKey('UseBasicParsing')) {
        $requestParams['UseBasicParsing'] = $true
    }
    if ($TimeoutSeconds -gt 0 -and $invokeWebRequestCmd -and $invokeWebRequestCmd.Parameters.ContainsKey('TimeoutSec')) {
        $requestParams['TimeoutSec'] = $TimeoutSeconds
    }
    if (-not [string]::IsNullOrWhiteSpace($InstanceId)) {
        $requestParams['Headers'] = @{ 'X-Elysium-Instance' = $InstanceId }
    }

    if ($normalizedMethod -in @('POST', 'PUT')) {
        $payload = [ordered]@{
            script   = 'Test-WeakADPasswords'
            version  = $ElysiumVersion
            ranAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
        if (-not [string]::IsNullOrWhiteSpace($InstanceId)) {
            $payload['instanceId'] = $InstanceId
        }
        $requestParams['ContentType'] = 'application/json'
        $requestParams['Body'] = ($payload | ConvertTo-Json -Depth 3 -Compress)
    }

    try {
        Invoke-WebRequest @requestParams | Out-Null
        Write-Verbose ("Usage beacon sent via {0}." -f $normalizedMethod)
    } catch {
        Write-Verbose ("Usage beacon failed: {0}" -f $_.Exception.Message)
    }
}

function Test-IsFipsPolicyEnabled {
    if (-not $onWindows) { return $false }
    try {
        $fipsReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -ErrorAction Stop
        return ([int]$fipsReg.Enabled -eq 1)
    } catch {
        return $false
    }
}

function Test-IsAdmin {
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = [Security.Principal.WindowsPrincipal]::new($wi)
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Ensure-NuGetAndPSGallery {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }
    try {
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        }
    } catch { Write-Verbose ("NuGet provider install warning: {0}" -f $_.Exception.Message) }
    # PSGallery is deliberately left untrusted: the operator already confirmed this install, and
    # -Force on Install-Module/Save-Module covers it without changing the host's repository policy.
}

function Ensure-ADModule {
    if (Get-Module -ListAvailable -Name ActiveDirectory) { return $true }
    Write-Warning "ActiveDirectory module not found."
    $resp = Read-Host "Install Active Directory PowerShell tools now? [Y/N]"
    if ($resp -notmatch '^(?i:y|yes)$') { return $false }
    if (-not (Test-IsAdmin)) { Write-Error 'Administrator rights are required to install AD tools.'; return $false }

    $installed = $false
    try {
        if (Get-Command -Name Install-WindowsFeature -ErrorAction SilentlyContinue) {
            try { Import-Module ServerManager -ErrorAction SilentlyContinue } catch {}
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop | Out-Null
            $installed = $true
        } elseif (Get-Command -Name Add-WindowsCapability -ErrorAction SilentlyContinue) {
            $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'Rsat.ActiveDirectory.DS-LDS.Tools*' } | Select-Object -First 1
            if ($cap) {
                Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
                $installed = $true
            } else {
                Write-Warning 'Could not locate RSAT ActiveDirectory capability.'
            }
        } else {
            Write-Warning 'No supported mechanism found to install AD tools automatically on this OS.'
        }
    } catch {
        Write-Error ("Failed to install AD tools: {0}" -f $_.Exception.Message)
    }
    if ($installed -and (Get-Module -ListAvailable -Name ActiveDirectory)) { return $true }
    return $false
}

function Ensure-DSInternalsModule {
    # On PS7+Windows we prefer installing into WindowsPowerShell modules so -UseWindowsPowerShell can load it
    $needWinPSPath = ($runningInPSCore -and $onWindows)
    $winPSModulesPath = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'

    $hasModule = $false
    if ($needWinPSPath) {
        # Quick check for presence in WinPS path
        $candidatePath = Join-Path $winPSModulesPath 'DSInternals'
        if (Test-Path $candidatePath) { $hasModule = $true }
    } else {
        $hasModule = [bool](Get-Module -ListAvailable -Name DSInternals)
    }
    if ($hasModule) { return $true }

    Write-Warning "DSInternals module not found."
    $resp = Read-Host "Install DSInternals from PowerShell Gallery now? [Y/N]"
    if ($resp -notmatch '^(?i:y|yes)$') { return $false }
    if (-not (Test-IsAdmin)) { Write-Error 'Administrator rights are required to install modules.'; return $false }

    try {
        Ensure-NuGetAndPSGallery
        if ($needWinPSPath) {
            if (-not (Test-Path $winPSModulesPath)) { New-Item -Path $winPSModulesPath -ItemType Directory -Force | Out-Null }
            Save-Module -Name DSInternals -Path $winPSModulesPath -Force -ErrorAction Stop
        } else {
            Install-Module -Name DSInternals -Scope AllUsers -Force -ErrorAction Stop
        }
    } catch {
        Write-Error ("Failed to install DSInternals: {0}" -f $_.Exception.Message)
        return $false
    }

    if ($needWinPSPath) {
        return (Test-Path (Join-Path $winPSModulesPath 'DSInternals'))
    } else {
        return [bool](Get-Module -ListAvailable -Name DSInternals)
    }
}

function Import-CompatModule {
    param(
        [Parameter(Mandatory)][string]$Name
    )
    $params = @{ Name = $Name; ErrorAction = 'Stop' }
    if ($runningInPSCore -and $onWindows) {
        $importCmd = Get-Command -Name Import-Module -CommandType Cmdlet -ErrorAction SilentlyContinue
        if ($importCmd -and $importCmd.Parameters.ContainsKey('UseWindowsPowerShell')) {
            $params['UseWindowsPowerShell'] = $true
        }
    }
    if ($Name -eq 'DSInternals') {
        # DSInternals can emit a FIPS MD5 warning via Write-Error during import; treat it as non-fatal if the module loads.
        $params['ErrorAction'] = 'SilentlyContinue'
        $importErrors = @()
        try {
            Import-Module @params -ErrorVariable +importErrors
        } catch {
            $fqid = [string]$_.FullyQualifiedErrorId
            $message = $_.Exception.Message
            $isFipsBootstrapError = ($fqid -match 'DSInternals\.Bootstrap\.psm1') -and ($message -match 'Only FIPS certified cryptographic algorithms are enabled in \.NET')
            if (-not $isFipsBootstrapError) { throw }
            Write-Warning "DSInternals bootstrap reported FIPS restrictions. Continuing if the module is available."
        }

        $moduleLoaded = [bool](Get-Module -Name $Name -ErrorAction SilentlyContinue)
        if (-not $moduleLoaded) {
            $fipsErrorSeen = @($importErrors | Where-Object { $_.Exception.Message -match 'Only FIPS certified cryptographic algorithms are enabled in \.NET' }).Count -gt 0
            if ($fipsErrorSeen) {
                throw "DSInternals could not be loaded under current FIPS policy. Use a host/policy that allows required algorithms for DSInternals."
            }
            if ($importErrors.Count -gt 0) { throw $importErrors[0] }
            throw "Failed to import module '$Name'."
        }

        $fipsErrors = @($importErrors | Where-Object { $_.Exception.Message -match 'Only FIPS certified cryptographic algorithms are enabled in \.NET' })
        if ($fipsErrors.Count -gt 0) {
            Write-Warning "DSInternals loaded under FIPS policy. MD5-dependent DSInternals checks may be limited."
        }

        $nonFipsErrors = @($importErrors | Where-Object { $_.Exception.Message -notmatch 'Only FIPS certified cryptographic algorithms are enabled in \.NET' })
        if ($nonFipsErrors.Count -gt 0) {
            $nonFipsMsg = $nonFipsErrors[0].Exception.Message
            if ($nonFipsMsg -match 'Zone\.Identifier|alternate data stream') {
                $dsModule = Get-Module -Name DSInternals -ErrorAction SilentlyContinue
                if (-not $dsModule) { $dsModule = Get-Module -ListAvailable -Name DSInternals -ErrorAction SilentlyContinue | Select-Object -First 1 }
                $dsPath = if ($dsModule) { $dsModule.ModuleBase } else { '<DSInternals module path>' }
                throw ("DSInternals native DLL is blocked by Windows (Zone.Identifier). Run the following on the target machine and retry:`n  Get-ChildItem -Path '$dsPath' -Recurse | Unblock-File")
            }
            Write-Warning ("DSInternals import reported non-fatal warning(s): {0}" -f $nonFipsMsg)
        }

        Write-Verbose ("Imported module '{0}' (Core={1}, Windows={2})" -f $Name, $runningInPSCore, $onWindows)
        return
    }

    Import-Module @params
    Write-Verbose ("Imported module '{0}' (Core={1}, Windows={2})" -f $Name, $runningInPSCore, $onWindows)
}

function Resolve-DSInternalsWeakHashFile {
    # DSInternals wants a sorted file of bare, upper-case, unique hashes. The KHDB that Update-ElysiumKhdb
    # builds already is one, so the normal case is one compiled pass over the file and no copy.
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Weak password hashes file not found at '$Path'."
    }

    Write-Host ("Checking weak password hashes file '{0}' ({1:N1} GB)..." -f $Path, ((Get-Item -LiteralPath $Path).Length / 1GB))
    $legacyEntryCount = [long]0
    $duplicateCount = [long]0
    $needsNormalization = $false
    [Elysium.KhdbText]::Inspect($Path, [ref]$legacyEntryCount, [ref]$duplicateCount, [ref]$needsNormalization)

    if (-not $needsNormalization) {
        return [pscustomobject]@{
            Path        = $Path
            IsTemporary = $false
        }
    }

    $tmpPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('elysium-khdb-' + [System.Guid]::NewGuid().ToString() + '.txt'))
    [void][Elysium.KhdbText]::WriteNormalized($Path, $tmpPath)

    $normalizationReasons = @()
    if ($legacyEntryCount -gt 0) { $normalizationReasons += "$legacyEntryCount legacy HASH:count entries" }
    if ($duplicateCount -gt 0) { $normalizationReasons += "$duplicateCount duplicate hashes" }
    if ($normalizationReasons.Count -eq 0) { $normalizationReasons += 'format normalization' }
    Write-Warning ("Normalized weak password hashes file for DSInternals compatibility ({0}). Temporary file: {1}" -f ($normalizationReasons -join ', '), $tmpPath)

    return [pscustomobject]@{
        Path        = $tmpPath
        IsTemporary = $true
    }
}

# Function to test for weak AD passwords
function Invoke-WeakPasswordTest {
    param (
        [hashtable]$DomainDetails,
        [string]$FilePath,
        [bool]$CheckOnlyEnabledUsers = $false,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$DomainName
    )

    $selectedDomain = Select-ElysiumDomain -DomainDetails $DomainDetails -Name $DomainName -Purpose 'test'
    Write-Verbose "Selected domain: $($selectedDomain.Name)"

    if ($null -eq $Credential) {
        $credential = Get-ValidatedADCredential -DomainName $selectedDomain.Name -Server $selectedDomain["DC"]
    } else {
        $credential = $Credential
        Write-Verbose ("Using credential supplied by caller: {0}" -f $credential.UserName)
    }

    # Pre-flight checks before attempting DCSync
    try {
        $domainInfo = Get-ADDomain -Server $selectedDomain["DC"] -Credential $credential -ErrorAction Stop
        Test-DCClockSkew -Server $selectedDomain["DC"] -Credential $credential
        Test-ReplicationPermissions -DomainDN $domainInfo.DistinguishedName `
            -Server $selectedDomain["DC"] -Credential $credential
    } catch {
        Write-Error $_.Exception.Message
        return
    }

    # Performing the test
    Write-Verbose "Testing password quality for $($selectedDomain.Name)..."
    $resolvedHashFile = $null
    try {
        $resolvedHashFile = Resolve-DSInternalsWeakHashFile -Path $FilePath
        $accounts = Get-ADReplAccount -All -Server $selectedDomain["DC"] -Credential $credential
        if ($CheckOnlyEnabledUsers) {
            Write-Verbose "Filtering to only enabled users per settings."
            # Prefer property 'Enabled' if present, fall back gracefully if not
            $accounts = $accounts | Where-Object {
                if ($_.PSObject.Properties.Name -contains 'Enabled') { $_.Enabled } else { $true }
            }
        }
        $testResults = $accounts | Test-PasswordQuality -WeakPasswordHashesSortedFile $resolvedHashFile.Path
        Write-Verbose "Password quality test completed."
    } catch {
        $ex = $_.Exception
        $diagLines = [System.Collections.Generic.List[string]]::new()
        $diagLines.Add('========================================')
        $diagLines.Add('ELYSIUM DCSYNC DIAGNOSTIC DUMP')
        $diagLines.Add('========================================')
        $diagLines.Add("Timestamp    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $diagLines.Add("Script Ver   : $ElysiumVersion")
        $diagLines.Add("PS Version   : $($PSVersionTable.PSVersion)")
        $diagLines.Add("PS Edition   : $($PSVersionTable.PSEdition)")
        $diagLines.Add("DSInternals  : $((Get-Module -Name DSInternals).Version)")
        $diagLines.Add("DC           : $($selectedDomain['DC'])")
        $diagLines.Add("Domain       : $($selectedDomain.Name)")
        $diagLines.Add("Account      : $($credential.UserName)")
        $diagLines.Add("DomainDN     : $($domainInfo.DistinguishedName)")
        $diagLines.Add("SchemaDN     : CN=Schema,CN=Configuration,$($domainInfo.DistinguishedName)")
        $diagLines.Add('')
        $diagLines.Add('--- EXCEPTION CHAIN ---')
        $depth = 0
        $currentEx = $ex
        while ($null -ne $currentEx) {
            $diagLines.Add("Exception $depth : $($currentEx.GetType().FullName)")
            $diagLines.Add("  Message    : $($currentEx.Message)")
            $diagLines.Add("  HResult    : 0x$($currentEx.HResult.ToString('X8'))")
            $diagLines.Add("  Source     : $($currentEx.Source)")
            if ($currentEx.TargetSite) {
                $diagLines.Add("  TargetSite : $($currentEx.TargetSite)")
            }
            if ($currentEx.StackTrace) {
                $diagLines.Add("  StackTrace :`n$($currentEx.StackTrace -replace '^', '    ')")
            }
            $diagLines.Add('')
            $currentEx = $currentEx.InnerException
            $depth++
        }
        $diagLines.Add('--- END DIAGNOSTIC DUMP ---')

        $diagText = $diagLines -join "`r`n"
        Write-Host $diagText -ForegroundColor Red

        $diagPath = Join-Path -Path $reportPathBase -ChildPath "dcsync-diag-$timestamp.txt"
        try {
            New-Item -ItemType Directory -Path $reportPathBase -Force | Out-Null
            [System.IO.File]::WriteAllText($diagPath, $diagText, [System.Text.Encoding]::UTF8)
            Write-Host ("Diagnostic dump written to: {0}" -f $diagPath)
        } catch {
            Write-Warning ("Could not write diagnostic dump to disk: {0}" -f $_.Exception.Message)
        }

        # Still emit the concise error for the operator
        $message = $ex.Message
        if ($message -match 'Replication access was denied|Access is denied') {
            Write-Error ("Replication access denied from '{0}' using '{1}'.`n`nDSInternals 7.0 fetches the AD schema via DRS before replicating accounts. The schema NC has its own ACL.`nGrant the 3 DCSync extended rights on BOTH:`n  1. {2}  (domain NC - for accounts)`n  2. CN=Configuration,{2}  (config NC - covers schema NC via inheritance)`n`nIn ADUC: right-click each object > Properties > Security > Advanced > Add the extended rights for '{1}'." -f `
                $selectedDomain["DC"], $credential.UserName, $domainInfo.DistinguishedName)
        } elseif ($message -match 'rejected the client credentials|unknown user name|bad password|logon failure') {
            Write-Error ("Credentials for '{0}' were rejected by '{1}'. Re-run and provide valid domain credentials." -f $credential.UserName, $selectedDomain["DC"])
        } else {
            Write-Error ("An error occurred while testing passwords: {0}" -f $message)
        }
        return
    } finally {
        if ($resolvedHashFile -and $resolvedHashFile.IsTemporary -and (Test-Path -LiteralPath $resolvedHashFile.Path)) {
            try { Remove-Item -LiteralPath $resolvedHashFile.Path -Force -ErrorAction Stop } catch { }
        }
    }

    # UPNs come from the accounts already replicated above - no extra LDAP lookup per account.
    $upnBySam = @{}
    foreach ($account in @($accounts)) {
        if ($account.SamAccountName -and $account.UserPrincipalName) { $upnBySam[[string]$account.SamAccountName] = [string]$account.UserPrincipalName }
    }

    # Report generation with dynamic content and UPNs
    $reportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_WeakPasswordReport_$timestamp.txt"
    $upnOnlyReportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_DictionaryPasswordUPNs_$timestamp.txt"

    # Build a lookup of SAM account names to UPNs for dictionary hits by leveraging structured results
    $dictionaryLogonNames = @()
    foreach ($result in @($testResults)) {
        if ($null -ne $result -and $null -ne $result.WeakPassword) {
            $dictionaryLogonNames += $result.WeakPassword
        }
    }
    $dictionaryLogonNames = $dictionaryLogonNames | Sort-Object -Unique

    $dictionarySamToUpn = @{}
    $upnReportContent = @()

    foreach ($logonName in $dictionaryLogonNames) {
        $samAccountName = $logonName -replace '^.*\\', ''
        if (-not [string]::IsNullOrWhiteSpace($samAccountName) -and -not $dictionarySamToUpn.ContainsKey($samAccountName)) {
            $upn = $upnBySam[$samAccountName]
            if ([string]::IsNullOrWhiteSpace($upn)) { $upn = "UPN not found" }
            $dictionarySamToUpn[$samAccountName] = $upn
            if ($upn -ne "UPN not found") {
                $upnReportContent += $upn
            }
        }
    }

    Write-Verbose "Generating report at $reportPath"
    # -Width prevents PowerShell's default table formatter from truncating long columns (e.g. a
    # long SamAccountName) at console/default width, which would otherwise silently break the
    # first-token re-parse below used to attach "UPN:" lines to dictionary hits.
    $reportContent = @($header, ($testResults | Out-String -Width 4096).Trim(), $footer) -join "`r`n"

    $lines = $reportContent -split "`r`n"
    $newReportContent = @()
    $collectingUPNs = $false

    foreach ($line in $lines) {
        $newReportContent += $line

        if ($line -match "Passwords of these accounts have been found in the dictionary:") {
            $collectingUPNs = $true
            continue
        }

        if ($collectingUPNs) {
            if ($line -match '^\s*$') { continue }
            if ($line -match '^\s*-{2,}') { continue }
            if ($line -match '^\s*(SamAccountName|LogonName)\b') { continue }
            if ($line -match '^[^\s].*:\s*$' -and $line -notmatch 'dictionary') {
                $collectingUPNs = $false
                continue
            }

            $firstToken = ($line.Trim() -split '\s+')[0]
            if (-not [string]::IsNullOrWhiteSpace($firstToken)) {
                $samAccountName = $firstToken -replace '^.*\\', ''
                if ($dictionarySamToUpn.ContainsKey($samAccountName)) {
                    $upnValue = $dictionarySamToUpn[$samAccountName]
                    $newReportContent += "    UPN: $upnValue"
                }
            }
        }
    }

    $updatedReportContent = $newReportContent -join "`r`n"
    $upnOnlyContent = $upnReportContent -join "`r`n"

    try {
        $updatedReportContent | Out-File -FilePath $reportPath -Encoding utf8 -ErrorAction Stop
        Write-Host "Report saved to $reportPath"

        $upnOnlyContent | Out-File -FilePath $upnOnlyReportPath -Encoding utf8 -ErrorAction Stop
        Write-Host "UPN-only report saved to $upnOnlyReportPath"

        $findings = @(ConvertTo-PasswordQualityFinding -Result $testResults -UpnBySam $upnBySam)
        $jsonReportPath = [System.IO.Path]::ChangeExtension($reportPath, '.json')
        $jsonReport = [ordered]@{
            tool             = 'Elysium'
            version          = $ElysiumVersion
            generatedAt      = (Get-Date).ToUniversalTime().ToString('o')
            domain           = $selectedDomain.Name
            domainController = $selectedDomain.DC
            accountsTested   = @($accounts).Count
            findings         = $findings
        }
        [System.IO.File]::WriteAllText($jsonReportPath, ($jsonReport | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
        Write-Host "JSON report saved to $jsonReportPath"
    } catch {
        Write-Error ("Failed to save report: {0}" -f $_.Exception.Message)
    }

    $findingCounts = [ordered]@{}
    foreach ($finding in $findings) { $findingCounts[$finding.check] = $finding.count }
    [pscustomobject]@{
        Domain         = $selectedDomain.Name
        AccountsTested = @($accounts).Count
        Findings       = $findingCounts
        ReportPath     = $reportPath
        JsonReportPath = $jsonReportPath
        UpnReportPath  = $upnOnlyReportPath
    }
}

function ConvertTo-PasswordQualityFinding {
    # Plain-data view of a DSInternals Test-PasswordQuality result for the JSON report: one finding per
    # non-empty result property (WeakPassword, LMHash, ...) listing its accounts with their UPNs.
    # DuplicatePasswordGroups stays grouped: each of its entries is a list of accounts sharing a password.
    # Arrays are built with List.ToArray(), not pipeline output: Windows PowerShell 5.1's ConvertTo-Json
    # serializes pipeline-wrapped arrays as {"value": [...], "Count": n}.
    param(
        [Parameter(Mandatory)][AllowNull()]$Result,
        [hashtable]$UpnBySam = @{}
    )

    $toAccount = { param($logonName) [ordered]@{ account = [string]$logonName; upn = $UpnBySam[([string]$logonName -replace '^.*\\', '')] } }
    foreach ($testResult in @($Result)) {
        if ($null -eq $testResult) { continue }
        foreach ($property in $testResult.PSObject.Properties) {
            $items = @($property.Value | Where-Object { $null -ne $_ })
            if ($items.Count -eq 0) { continue }
            $accounts = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $items) {
                if ($item -is [string]) {
                    $accounts.Add((& $toAccount $item))
                } else {
                    $group = [System.Collections.Generic.List[object]]::new()
                    foreach ($member in $item) { $group.Add((& $toAccount $member)) }
                    $accounts.Add($group.ToArray())
                }
            }
            [ordered]@{ check = $property.Name; count = $items.Count; accounts = $accounts.ToArray() }
        }
    }
}
