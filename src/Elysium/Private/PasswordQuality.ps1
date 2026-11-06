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
        [string]$DomainName,
        [int]$RecentPasswordWindowDays = 180
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

    # Per-account metadata from the already-replicated accounts - no extra LDAP lookup. PasswordLastSet
    # drives the "set before vs after the filter knew the hash" split; AdminCount flags privileged hits.
    # PasswordLastSet/AdminCount/Enabled are read through property-name guards so a DSInternals object
    # that lacks one degrades to "unknown age" instead of throwing under Set-StrictMode.
    $upnBySam = @{}
    $accountMeta = @{}
    foreach ($account in @($accounts)) {
        $sam = [string]$account.SamAccountName
        if ([string]::IsNullOrWhiteSpace($sam)) { continue }
        $upn = [string]$account.UserPrincipalName
        if (-not [string]::IsNullOrWhiteSpace($upn)) { $upnBySam[$sam] = $upn }
        $plsProp = $account.PSObject.Properties['PasswordLastSet']
        if (-not $plsProp) { $plsProp = $account.PSObject.Properties['PwdLastSet'] }
        $acProp = $account.PSObject.Properties['AdminCount']
        $enProp = $account.PSObject.Properties['Enabled']
        $accountMeta[$sam] = [pscustomobject]@{
            Sam             = $sam
            Upn             = $upn
            PasswordLastSet = if ($plsProp) { $plsProp.Value } else { $null }
            AdminCount      = [bool]($acProp -and $acProp.Value)
            Enabled         = if ($enProp) { [bool]$enProp.Value } else { $true }
        }
    }

    # Report generation with dynamic content and UPNs
    $reportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_WeakPasswordReport_$timestamp.txt"
    $upnOnlyReportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_DictionaryPasswordUPNs_$timestamp.txt"
    # Set before the report try so the return value stays valid even if report writing throws.
    $htmlReportPath = [System.IO.Path]::ChangeExtension($reportPath, '.html')
    $forceResetListPath = $null
    $forceResetScriptPath = $null
    $analysis = $null

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

        # Features 1-4: pwdLastSet age split, filter-efficacy headline, run-over-run trend, force-reset list.
        $analysis = Get-WeakPasswordAnalysis -Findings $findings -AccountMeta $accountMeta -WindowDays $RecentPasswordWindowDays `
            -ReportPathBase $reportPathBase -DomainName $selectedDomain.Name -CurrentJsonPath $jsonReportPath

        $html = New-PasswordQualityHtmlReport -Analysis $analysis -Findings $findings -Domain $selectedDomain.Name `
            -DomainController ([string]$selectedDomain.DC) -AccountsTested (@($accounts).Count)
        [System.IO.File]::WriteAllText($htmlReportPath, $html, [System.Text.UTF8Encoding]::new($false))
        Write-Host "HTML report saved to $htmlReportPath"

        $resetListCandidate = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_ForceReset_$timestamp.txt"
        $resetScriptCandidate = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_ForceReset_$timestamp.ps1"
        $resetArtifacts = Export-ForceResetArtifacts -Analysis $analysis -Domain $selectedDomain.Name -ListPath $resetListCandidate -ScriptPath $resetScriptCandidate
        if ($resetArtifacts) {
            $forceResetListPath = $resetArtifacts.ListPath
            $forceResetScriptPath = $resetArtifacts.ScriptPath
            Write-Host ("Force-reset work list saved to {0} ({1} enabled account(s))" -f $forceResetListPath, $resetArtifacts.Count)
            Write-Host "Force-reset script (REVIEW before running) saved to $forceResetScriptPath"
        }
    } catch {
        Write-Error ("Failed to save report: {0}" -f $_.Exception.Message)
    }

    if ($analysis) {
        Write-Host ''
        if (@($analysis.WeakRecent).Count -gt 0) {
            Write-Host ("[!] FILTER GAP: {0} account(s) had a known-weak password set in the last {1} days - the password filter is not blocking these." -f @($analysis.WeakRecent).Count, $analysis.WindowDays) -ForegroundColor Red
        } else {
            Write-Host ("[+] No known-weak passwords set in the last {0} days - the live filter appears effective." -f $analysis.WindowDays) -ForegroundColor Green
        }
        if ($analysis.Trend.HasPrior) {
            Write-Host ("    Trend vs previous run: {0} new, {1} remediated, {2} still weak." -f @($analysis.Trend.NewWeak).Count, @($analysis.Trend.Remediated).Count, @($analysis.Trend.Repeat).Count)
        }
    }

    $findingCounts = [ordered]@{}
    foreach ($finding in $findings) { $findingCounts[$finding.check] = $finding.count }
    [pscustomobject]@{
        Domain                   = $selectedDomain.Name
        AccountsTested           = @($accounts).Count
        Findings                 = $findingCounts
        WeakTotal                = if ($analysis) { $analysis.WeakTotal } else { 0 }
        WeakSetWithinWindow      = if ($analysis) { @($analysis.WeakRecent).Count } else { 0 }
        RecentPasswordWindowDays = $RecentPasswordWindowDays
        ReportPath               = $reportPath
        HtmlReportPath           = $htmlReportPath
        JsonReportPath           = $jsonReportPath
        UpnReportPath            = $upnOnlyReportPath
        ForceResetListPath       = $forceResetListPath
        ForceResetScriptPath     = $forceResetScriptPath
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

function Get-PriorWeakPasswordSams {
    # Loads the most recent prior <domain>_WeakPasswordReport_*.json and returns its WeakPassword SAMs,
    # for the run-over-run trend. ponytail: prior-vs-current only (one file), not full history - enough
    # for new/remediated/repeat; read more files here if a multi-run streak is ever wanted.
    param([string]$ReportPathBase, [string]$DomainName, [string]$CurrentJsonPath)

    $result = [pscustomobject]@{ HasPrior = $false; Path = $null; WeakSams = @() }
    try {
        if ([string]::IsNullOrWhiteSpace($ReportPathBase) -or -not (Test-Path -LiteralPath $ReportPathBase)) { return $result }
        $currentLeaf = if ($CurrentJsonPath) { Split-Path -Path $CurrentJsonPath -Leaf } else { '' }
        $pattern = '{0}_WeakPasswordReport_*.json' -f $DomainName
        $candidates = @(Get-ChildItem -LiteralPath $ReportPathBase -Filter $pattern -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne $currentLeaf } |
            Sort-Object Name -Descending)      # names are timestamped, so lexical order == chronological
        if ($candidates.Count -eq 0) { return $result }

        $prior = $candidates[0]
        $json = Get-Content -LiteralPath $prior.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
        $sams = [System.Collections.Generic.List[string]]::new()
        foreach ($finding in @($json.findings | Where-Object { $_.check -eq 'WeakPassword' })) {
            foreach ($a in @($finding.accounts)) {
                $sam = [string]$a.account -replace '^.*\\', ''
                if (-not [string]::IsNullOrWhiteSpace($sam)) { $sams.Add($sam) }
            }
        }
        $result.HasPrior = $true
        $result.Path = $prior.FullName
        $result.WeakSams = @($sams | Sort-Object -Unique)
    } catch { }
    return $result
}

function Get-WeakPasswordAnalysis {
    # The filter prevents weak passwords at change time; it never rescans what is already set. So the
    # value is the time axis: of the accounts whose password is in the KHDB, which were set *after* the
    # filter knew that hash (a live gap) versus *before* (legacy backlog). Also flags privileged hits
    # and diffs against the previous run.
    param(
        [Parameter(Mandatory)][AllowNull()]$Findings,
        [hashtable]$AccountMeta = @{},
        [int]$WindowDays = 180,
        [string]$ReportPathBase,
        [string]$DomainName,
        [string]$CurrentJsonPath
    )

    $window = [math]::Abs($WindowDays)
    $now = Get-Date
    $cutoff = $now.AddDays(-$window)

    $recent = [System.Collections.Generic.List[object]]::new()
    $backlog = [System.Collections.Generic.List[object]]::new()
    $unknown = [System.Collections.Generic.List[object]]::new()
    $privileged = [System.Collections.Generic.List[object]]::new()
    $currentSams = [System.Collections.Generic.List[string]]::new()

    $weakFinding = @($Findings | Where-Object { $_.check -eq 'WeakPassword' }) | Select-Object -First 1
    if ($weakFinding) {
        foreach ($a in @($weakFinding.accounts)) {
            $logon = [string]$a.account
            $sam = $logon -replace '^.*\\', ''
            if ([string]::IsNullOrWhiteSpace($sam)) { continue }
            $currentSams.Add($sam)

            $meta = $null
            if ($AccountMeta.ContainsKey($sam)) { $meta = $AccountMeta[$sam] }
            $pls = if ($meta) { $meta.PasswordLastSet } else { $null }
            $adminCount = [bool]($meta -and $meta.AdminCount)
            $enabled = if ($meta) { [bool]$meta.Enabled } else { $true }
            $upn = ''
            if ($meta -and $meta.Upn) { $upn = [string]$meta.Upn } elseif ($a.upn) { $upn = [string]$a.upn }

            $ageDays = $null
            $bucket = 'Unknown'
            if ($pls -is [datetime]) {
                $ageDays = [int][math]::Floor(($now - $pls).TotalDays)
                $bucket = if ($pls -ge $cutoff) { 'Recent' } else { 'Backlog' }
            }

            $rec = [pscustomobject]@{
                Sam = $sam; Logon = $logon; Upn = $upn; PasswordLastSet = $pls
                AgeDays = $ageDays; AdminCount = $adminCount; Enabled = $enabled; Bucket = $bucket
            }
            switch ($bucket) {
                'Recent'  { $recent.Add($rec) }
                'Backlog' { $backlog.Add($rec) }
                default   { $unknown.Add($rec) }
            }
            if ($adminCount) { $privileged.Add($rec) }
        }
    }

    $prior = Get-PriorWeakPasswordSams -ReportPathBase $ReportPathBase -DomainName $DomainName -CurrentJsonPath $CurrentJsonPath
    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    $priorSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($prior.WeakSams), $cmp)
    $curSet = [System.Collections.Generic.HashSet[string]]::new($cmp)
    foreach ($s in $currentSams) { [void]$curSet.Add($s) }
    $newWeak = @(@($curSet) | Where-Object { -not $priorSet.Contains($_) } | Sort-Object)
    $remediated = @(@($prior.WeakSams) | Where-Object { -not $curSet.Contains($_) } | Sort-Object)
    $repeat = @(@($curSet) | Where-Object { $priorSet.Contains($_) } | Sort-Object)

    [pscustomobject]@{
        WindowDays     = $window
        GeneratedAt    = $now
        WeakTotal      = $curSet.Count
        WeakRecent     = $recent
        WeakBacklog    = $backlog
        WeakUnknown    = $unknown
        PrivilegedWeak = $privileged
        Trend          = [pscustomobject]@{
            HasPrior       = $prior.HasPrior
            PriorPath      = $prior.Path
            PriorWeakTotal = @($prior.WeakSams).Count
            NewWeak        = $newWeak
            Remediated     = $remediated
            Repeat         = $repeat
            Delta          = ($curSet.Count - @($prior.WeakSams).Count)
        }
    }
}

function Export-ForceResetArtifacts {
    # The filter cannot fix a password already set; only a reset can. Writes the enabled weak accounts
    # as a plain SAM work list plus a reviewed, NOT auto-run, script that flags each to change at next
    # logon. Operator reviews and runs the script by hand. Returns $null when there is nothing to reset.
    param(
        [Parameter(Mandatory)]$Analysis,
        [string]$Domain,
        [string]$ListPath,
        [string]$ScriptPath
    )

    $records = @()
    $records += @($Analysis.WeakRecent)
    $records += @($Analysis.WeakBacklog)
    $records += @($Analysis.WeakUnknown)
    # Only enabled accounts are worth resetting; disabled ones carry no live logon risk.
    $targets = @($records | Where-Object { $_.Enabled } | Sort-Object Sam -Unique)
    if ($targets.Count -eq 0) { return $null }
    $sams = @($targets | ForEach-Object { $_.Sam })

    [System.IO.File]::WriteAllLines($ListPath, [string[]]$sams, [System.Text.UTF8Encoding]::new($false))

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Elysium force-reset script - REVIEW BEFORE RUNNING.')
    [void]$sb.AppendLine('# Flags each listed account so the user must change their password at next logon.')
    [void]$sb.AppendLine('# Every account here holds a password found in the known-compromised hash database.')
    [void]$sb.AppendLine(('# Domain: {0}   Generated: {1}   Accounts: {2}' -f $Domain, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $sams.Count))
    [void]$sb.AppendLine('# Requires the RSAT ActiveDirectory module and rights to reset these accounts.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("`$ErrorActionPreference = 'Stop'")
    [void]$sb.AppendLine('Import-Module ActiveDirectory')
    [void]$sb.AppendLine('$accounts = @(')
    foreach ($s in $sams) {
        [void]$sb.AppendLine(("    '{0}'," -f ($s -replace "'", "''")))
    }
    [void]$sb.AppendLine(')')
    [void]$sb.AppendLine('foreach ($sam in $accounts) {')
    [void]$sb.AppendLine('    try {')
    [void]$sb.AppendLine('        Set-ADUser -Identity $sam -ChangePasswordAtLogon $true')
    [void]$sb.AppendLine('        Write-Host "[+] $sam flagged to change password at next logon."')
    [void]$sb.AppendLine('    } catch {')
    [void]$sb.AppendLine('        Write-Warning "[-] $sam : $($_.Exception.Message)"')
    [void]$sb.AppendLine('    }')
    [void]$sb.AppendLine('}')
    [System.IO.File]::WriteAllText($ScriptPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

    return [pscustomobject]@{ ListPath = $ListPath; ScriptPath = $ScriptPath; Count = $sams.Count }
}

function Get-ElysiumReportCss {
    # Self-contained, light/dark via prefers-color-scheme. ponytail: inline CSS, no JS, no libraries.
    @'
:root{--bg:#f6f7f9;--fg:#1a1d21;--muted:#6b7280;--card:#fff;--line:#e5e7eb;--bad:#c0392b;--badbg:#fdecea;--good:#1e7e45;--goodbg:#e8f5ee}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8eb;--muted:#9aa3ad;--card:#171a20;--line:#2a2f37;--bad:#ff6b5e;--badbg:#2a1715;--good:#5bd98a;--goodbg:#13241a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 56px}
header h1{margin:0 0 4px;font-size:22px}
.sub{color:var(--muted);margin:0 0 20px;font-size:13px}
h2{font-size:17px;margin:28px 0 10px}
h2.warn{color:var(--bad)}
.verdict{border:1px solid var(--line);border-left-width:5px;border-radius:8px;padding:14px 16px;margin:8px 0 4px;background:var(--card)}
.verdict h2{margin:0 0 6px}
.verdict.bad{border-left-color:var(--bad);background:var(--badbg)}
.verdict.good{border-left-color:var(--good);background:var(--goodbg)}
.verdict.bad h2{color:var(--bad)}.verdict.good h2{color:var(--good)}
.verdict p{margin:0;font-size:14px}
.stats{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{flex:1 1 140px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .v{font-size:26px;font-weight:700}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.bad .v{color:var(--bad)}.card.good .v{color:var(--good)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{background:rgba(127,127,127,.08);font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
tr:last-child td{border-bottom:none}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.small{font-size:12px;color:var(--muted)}
.muted{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600}
.badge.priv{background:var(--badbg);color:var(--bad)}
.badge.dis{background:rgba(127,127,127,.15);color:var(--muted)}
footer{margin-top:36px;border-top:1px solid var(--line);padding-top:12px}
'@
}

function New-ElysiumStatCard {
    param([string]$Label, $Value, [string]$Class = '')
    return ('<div class="card {0}"><div class="v">{1}</div><div class="l">{2}</div></div>' -f `
        $Class, [System.Net.WebUtility]::HtmlEncode([string]$Value), [System.Net.WebUtility]::HtmlEncode($Label))
}

function Format-WeakRecordTableHtml {
    param($Records, [string]$EmptyText = 'None.')
    $recs = @($Records)
    if ($recs.Count -eq 0) { return ('<p class="muted">{0}</p>' -f [System.Net.WebUtility]::HtmlEncode($EmptyText)) }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<table><thead><tr><th>Account</th><th>UPN</th><th>Password last set</th><th>Age (days)</th><th>Flags</th></tr></thead><tbody>')
    foreach ($r in ($recs | Sort-Object @{ Expression = { $_.AdminCount }; Descending = $true }, @{ Expression = { $_.AgeDays } })) {
        $pls = if ($r.PasswordLastSet -is [datetime]) { $r.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'unknown' }
        $age = if ($null -ne $r.AgeDays) { [string]$r.AgeDays } else { '&mdash;' }
        $flags = @()
        if ($r.AdminCount) { $flags += '<span class="badge priv">privileged</span>' }
        if (-not $r.Enabled) { $flags += '<span class="badge dis">disabled</span>' }
        [void]$sb.AppendLine(('<tr><td class="mono">{0}</td><td class="mono">{1}</td><td>{2}</td><td class="num">{3}</td><td>{4}</td></tr>' -f `
            [System.Net.WebUtility]::HtmlEncode($r.Sam),
            [System.Net.WebUtility]::HtmlEncode($r.Upn),
            $pls, $age, ($flags -join ' ')))
    }
    [void]$sb.AppendLine('</tbody></table>')
    return $sb.ToString()
}

function New-PasswordQualityHtmlReport {
    # "Nicer report": a self-contained HTML page built around the filter-gap story, with the age split,
    # trend, privileged callout and the remaining DSInternals hygiene findings. Plain text + JSON still
    # ship alongside it. All account-derived values are HTML-encoded (the page may be opened in a browser).
    param(
        [Parameter(Mandatory)]$Analysis,
        [AllowNull()]$Findings,
        [string]$Domain,
        [string]$DomainController,
        [int]$AccountsTested
    )

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $recent = @($Analysis.WeakRecent); $backlog = @($Analysis.WeakBacklog); $unknown = @($Analysis.WeakUnknown)
    $priv = @($Analysis.PrivilegedWeak)
    $win = $Analysis.WindowDays
    $gen = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    if ($recent.Count -gt 0) {
        $vClass = 'bad'
        $vTitle = ('Filter gap &mdash; {0} weak password(s) set in the last {1} days' -f $recent.Count, $win)
        $vBody = 'These accounts hold a password from the known-compromised database that was set <strong>after</strong> it became known. The live password filter did not block them. Check filter coverage: the DLL missing on a domain controller, an OU exclusion, or out-of-band / service-account changes.'
    } else {
        $vClass = 'good'
        $vTitle = ('No weak passwords set in the last {0} days' -f $win)
        $vBody = 'Every known-weak password predates the window, so the live filter appears to be blocking new weak passwords. The findings below are standing backlog to drain with a forced reset.'
    }

    $desc = @{
        WeakPassword               = 'Password hash found in the known-compromised (KHDB) database.'
        DuplicatePasswordGroups    = 'Accounts sharing the same password (password reuse).'
        LMHash                     = 'Weak LM hash stored - legacy, trivially cracked.'
        ClearTextPassword          = 'Password stored with reversible encryption.'
        EmptyPassword              = 'No password set.'
        PasswordNotRequired        = 'PASSWD_NOTREQD set - the account may have a blank password.'
        PasswordNeverExpires       = 'Password never expires.'
        AESKeysMissing             = 'Kerberos AES keys missing - password unchanged since the 2008 functional level.'
        PreAuthNotRequired         = 'Kerberos pre-authentication disabled (AS-REP roastable).'
        Kerberoastable             = 'Has a service principal name (Kerberoastable).'
        DESEncryptionOnly          = 'Restricted to weak DES encryption.'
        SmartCardUsersWithPassword = 'Smart-card-required account that still has a password hash.'
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>Elysium weak-password report &mdash; {0}</title>' -f (& $enc $Domain)))
    [void]$sb.AppendLine('<style>' + (Get-ElysiumReportCss) + '</style></head><body><main>')
    [void]$sb.AppendLine(('<header><h1>Elysium weak-password report</h1><p class="sub">{0} &middot; DC {1} &middot; {2} accounts tested &middot; generated {3}</p></header>' -f `
        (& $enc $Domain), (& $enc $DomainController), $AccountsTested, (& $enc $gen)))

    [void]$sb.AppendLine(('<section class="verdict {0}"><h2>{1}</h2><p>{2}</p></section>' -f $vClass, $vTitle, $vBody))

    [void]$sb.AppendLine('<section class="stats">')
    [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Weak total' -Value $Analysis.WeakTotal))
    [void]$sb.AppendLine((New-ElysiumStatCard -Label ("Set in last $win d") -Value $recent.Count -Class $(if ($recent.Count) { 'bad' } else { 'good' })))
    [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Legacy backlog' -Value $backlog.Count))
    [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Privileged' -Value $priv.Count -Class $(if ($priv.Count) { 'bad' } else { '' })))
    if ($unknown.Count) { [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Unknown age' -Value $unknown.Count)) }
    [void]$sb.AppendLine('</section>')

    $t = $Analysis.Trend
    if ($t.HasPrior) {
        $deltaTxt = if ($t.Delta -gt 0) { "+$($t.Delta)" } else { [string]$t.Delta }
        [void]$sb.AppendLine('<h2>Change since the previous run</h2><section class="stats">')
        [void]$sb.AppendLine((New-ElysiumStatCard -Label 'New' -Value @($t.NewWeak).Count -Class $(if (@($t.NewWeak).Count) { 'bad' } else { 'good' })))
        [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Remediated' -Value @($t.Remediated).Count -Class 'good'))
        [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Still weak (repeat)' -Value @($t.Repeat).Count))
        [void]$sb.AppendLine((New-ElysiumStatCard -Label 'Net change' -Value $deltaTxt))
        [void]$sb.AppendLine('</section>')
    } else {
        [void]$sb.AppendLine('<p class="muted">No previous report found for this domain &mdash; trend starts from the next run.</p>')
    }

    if ($priv.Count -gt 0) {
        [void]$sb.AppendLine('<section><h2 class="warn">Privileged accounts with weak passwords</h2>')
        [void]$sb.AppendLine((Format-WeakRecordTableHtml -Records $priv))
        [void]$sb.AppendLine('</section>')
    }

    [void]$sb.AppendLine(('<section><h2 class="warn">Weak password set in the last {0} days (filter gap)</h2>' -f $win))
    [void]$sb.AppendLine((Format-WeakRecordTableHtml -Records $recent -EmptyText 'None - nothing slipped past the filter in this window.'))
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<section><h2>Legacy backlog (password set before the window)</h2>')
    [void]$sb.AppendLine((Format-WeakRecordTableHtml -Records $backlog))
    [void]$sb.AppendLine('</section>')

    if ($unknown.Count -gt 0) {
        [void]$sb.AppendLine('<section><h2>Weak, password age unknown</h2>')
        [void]$sb.AppendLine((Format-WeakRecordTableHtml -Records $unknown))
        [void]$sb.AppendLine('</section>')
    }

    $other = @($Findings | Where-Object { $_.check -ne 'WeakPassword' })
    [void]$sb.AppendLine('<section><h2>Other account-hygiene findings</h2>')
    if ($other.Count -eq 0) {
        [void]$sb.AppendLine('<p class="muted">None.</p>')
    } else {
        [void]$sb.AppendLine('<table><thead><tr><th>Check</th><th>Count</th><th>What it means</th><th>Sample accounts</th></tr></thead><tbody>')
        foreach ($f in ($other | Sort-Object { - [int]$_.count })) {
            $names = [System.Collections.Generic.List[string]]::new()
            foreach ($a in @($f.accounts)) {
                if ($a -is [string]) { $names.Add($a) }
                elseif ($a -is [System.Collections.IEnumerable] -and $a -isnot [System.Collections.IDictionary]) {
                    foreach ($m in $a) { if ($m.account) { $names.Add([string]$m.account) } }
                } elseif ($a.account) { $names.Add([string]$a.account) }
                if ($names.Count -ge 12) { break }
            }
            $sample = (@($names) | Select-Object -First 12 | ForEach-Object { & $enc $_ }) -join ', '
            if (@($f.accounts).Count -gt $names.Count) { $sample += ' &hellip;' }
            $d = if ($desc.ContainsKey([string]$f.check)) { $desc[[string]$f.check] } else { '' }
            [void]$sb.AppendLine(('<tr><td class="mono">{0}</td><td class="num">{1}</td><td>{2}</td><td class="mono small">{3}</td></tr>' -f `
                (& $enc $f.check), $f.count, (& $enc $d), $sample))
        }
        [void]$sb.AppendLine('</tbody></table>')
    }
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<footer><p class="muted">Elysium &middot; a detective control for passwords already set in AD. The password filter prevents weak passwords at change time; this report finds the ones already there.</p></footer>')
    [void]$sb.AppendLine('</main></body></html>')
    return $sb.ToString()
}
