##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##          Move fast and fix things.           ##
##################################################
## Project: Elysium                             ##
## File: Test-WeakADPasswords.ps1               ##
## Version: 2.4.6                               ##
## Support: support@cqre.net                    ##
##################################################

<#
#Requires -Modules DSInternals, ActiveDirectory
.SYNOPSIS
Weak AD password finder component of Elysium tool.

.DESCRIPTION
This script will test the passwords of selected domain (defined in ElysiumSettings.txt) using DSInternals' Test-PasswordQuality cmdlet. It writes its output to a report file which is meant to be shared with the internal security team. The report now includes UPNs for each account mentioned.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithWindowsPowerShellIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

$VerbosePreference = "SilentlyContinue"

$scriptRoot = $PSScriptRoot

# Ensure consistent UTF-8 output for files across PS5.1/PS7
try {
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
    $PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8'
    $PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
    # Also align $OutputEncoding for external writes
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch { }

function Start-TestTranscript {
    param([string]$BasePath)
    try {
        $logsDir = Join-Path -Path $BasePath -ChildPath 'Reports/logs'
        if (-not (Test-Path $logsDir)) { New-Item -Path $logsDir -ItemType Directory -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path -Path $logsDir -ChildPath "test-weakad-$ts.log"
        Start-Transcript -Path $logPath -Force | Out-Null
    } catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

function Stop-TestTranscript { try { Stop-Transcript | Out-Null } catch {} }

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

# Current timestamp for both report generation and header
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Define Header and Footer for the report with dynamic date
$header = @"
=========== Elysium Report ==========
Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
=====================================

"@
$footer = "`r`n==== End of Report ===="

Start-TestTranscript -BasePath $scriptRoot
try {
    Write-Verbose "Loading settings..."
    $ElysiumSettings = Read-ElysiumSettings -ScriptRoot $scriptRoot
    Write-Verbose "Settings loaded successfully."

    $usageBeaconUrl = $ElysiumSettings['UsageBeaconUrl']
    $usageBeaconMethod = $ElysiumSettings['UsageBeaconMethod']
    $usageBeaconInstanceId = $ElysiumSettings['UsageBeaconInstanceId']
    $usageBeaconTimeoutSeconds = $null
    if ($ElysiumSettings.ContainsKey('UsageBeaconTimeoutSeconds')) {
        $parsedTimeout = 0
        if ([int]::TryParse($ElysiumSettings['UsageBeaconTimeoutSeconds'], [ref]$parsedTimeout)) {
            $usageBeaconTimeoutSeconds = $parsedTimeout
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($usageBeaconUrl)) {
        $beaconParams = @{ Url = $usageBeaconUrl }
        if (-not [string]::IsNullOrWhiteSpace($usageBeaconMethod)) {
            $beaconParams['Method'] = $usageBeaconMethod
        }
        if (-not [string]::IsNullOrWhiteSpace($usageBeaconInstanceId)) {
            $beaconParams['InstanceId'] = $usageBeaconInstanceId
        }
        if ($null -ne $usageBeaconTimeoutSeconds) {
            $beaconParams['TimeoutSeconds'] = $usageBeaconTimeoutSeconds
        }
        Invoke-UsageBeacon @beaconParams
    }

# Define the function to extract domain details from settings
function Get-DomainDetailsFromSettings {
    param (
        [hashtable]$Settings
    )

    $domainDetails = [ordered]@{}
    $counter = 1
    while ($true) {
        $nameKey = "Domain${counter}Name"
        $dcKey = "Domain${counter}DC"
        if ($Settings.ContainsKey($nameKey)) {
            $domainDetails["$counter"] = @{
                Name = $Settings[$nameKey]
                DC   = $Settings[$dcKey]
            }
            $counter++
        }
        else {
            break
        }
    }
    return $domainDetails
}

# Continue with script logic...
$domainDetails = Get-DomainDetailsFromSettings -Settings $ElysiumSettings
Write-Verbose ("Domain details extracted: {0}" -f ($domainDetails | ConvertTo-Json))

# Import required modules with PowerShell 7 compatibility
# - On Windows PowerShell: Import normally
# - On PowerShell 7+ on Windows: Import using -UseWindowsPowerShell if available
# - On non-Windows Core: not supported for AD/DSInternals
$runningInPSCore = ($PSVersionTable.PSEdition -eq 'Core')
$onWindows = ($env:OS -match 'Windows') -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
try { $osProductType = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType } catch { $osProductType = 1 }
$isServerOS = $onWindows -and ($osProductType -ne 1)

if ($runningInPSCore -and -not $onWindows) {
    throw 'This script requires Windows when running under PowerShell 7 (AD/DSInternals are Windows-only).'
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

if (Test-IsFipsPolicyEnabled) {
    throw @"
FIPS policy is enabled on this host (HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled = 1).
Test-WeakADPasswords uses DSInternals/AD replication operations that are not fully compatible with this policy in this environment.

Remediation:
1. Run this script from a dedicated non-FIPS workstation/jump host.
2. If approved by your security policy, temporarily disable local FIPS policy for this host, run the test, then re-enable it.
3. If FIPS must remain enforced, use an alternative fully FIPS-validated workflow/tool for weak password assessment.
"@
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

try {
    Import-CompatModule -Name 'ActiveDirectory'
} catch {
    Write-Warning ("ActiveDirectory import failed: {0}" -f $_.Exception.Message)
    if (Ensure-ADModule) {
        Import-CompatModule -Name 'ActiveDirectory'
    } else {
        throw "Failed to import ActiveDirectory module. On PS7, ensure RSAT AD tools are installed and Windows PowerShell 5.1 is present."
    }
}

try {
    Import-CompatModule -Name 'DSInternals'
} catch {
    Write-Warning ("DSInternals import failed: {0}" -f $_.Exception.Message)
    if (Ensure-DSInternalsModule) {
        Import-CompatModule -Name 'DSInternals'
    } else {
        throw "Failed to import DSInternals module. Try installing from PSGallery or placing it under '$env:ProgramFiles\WindowsPowerShell\Modules'."
    }
}

# Version check: v6.2 was unsigned (blocks native DLLs, causes replication failures);
# v7.0 fixes intermittent CRC errors mid-replication and Test-PasswordQuality result truncation.
$dsInternalsVersion = (Get-Module -Name DSInternals).Version
$minimumVersion = [version]'7.0'
$unsignedVersion = [version]'6.2'
if ($dsInternalsVersion -eq $unsignedVersion) {
    Write-Warning ("DSInternals {0} is not digitally signed, which blocks its native DLLs and causes replication failures. Update to v7.0+: Install-Module DSInternals -Force -AllowClobber" -f $dsInternalsVersion)
} elseif ($dsInternalsVersion -lt $minimumVersion) {
    $resp = Read-Host ("DSInternals {0} is installed; v7.0 fixes intermittent replication CRC errors and result truncation. Update now? [Y/N]" -f $dsInternalsVersion)
    if ($resp -match '^(?i:y|yes)$') {
        try {
            # Install-Module -Force is used instead of Update-Module to avoid a PowerShellGet bug
            # where null PublishedDate metadata causes "cannot convert null to type system.datetime"
            Install-Module -Name DSInternals -Force -AllowClobber -ErrorAction Stop
            Write-Host '[+] DSInternals updated. Please re-run the script to load the new version.'
            exit 0
        } catch {
            Write-Warning ("DSInternals update failed: {0}" -f $_.Exception.Message)
        }
    }
}

# Resolve KHDB path with fallbacks
$installationPath = $ElysiumSettings["InstallationPath"]
if ([string]::IsNullOrWhiteSpace($installationPath)) { $installationPath = $scriptRoot }
elseif (-not [System.IO.Path]::IsPathRooted($installationPath)) { $installationPath = Join-Path -Path $scriptRoot -ChildPath $installationPath }

$khdbName = if ([string]::IsNullOrWhiteSpace($ElysiumSettings["WeakPasswordsDatabase"])) { 'khdb.txt' } else { $ElysiumSettings["WeakPasswordsDatabase"] }
$WeakHashesSortedFilePath = Join-Path -Path $installationPath -ChildPath $khdbName
if (-not (Test-Path $WeakHashesSortedFilePath)) {
    Write-Error "Weak password hashes file not found at '$WeakHashesSortedFilePath'."
    exit
}
Write-Verbose "Weak password hashes file found at '$WeakHashesSortedFilePath'."

# Ensure the report directory exists (relative paths resolved against script root)
$reportPathBase = $ElysiumSettings["ReportPathBase"]
if ([string]::IsNullOrWhiteSpace($reportPathBase)) { $reportPathBase = 'Reports' }
if (-not [System.IO.Path]::IsPathRooted($reportPathBase)) { $reportPathBase = Join-Path -Path $scriptRoot -ChildPath $reportPathBase }
if (-not (Test-Path -Path $reportPathBase)) {
    try {
        New-Item -Path $reportPathBase -ItemType Directory -ErrorAction Stop | Out-Null
        Write-Verbose "Report directory created at '$reportPathBase'."
    } catch {
        Write-Error ("Failed to create report directory: {0}" -f $_.Exception.Message)
        exit
    }
}

# Read filtering flag (defaults to false)
$checkOnlyEnabledUsers = $false
if ($ElysiumSettings.ContainsKey('CheckOnlyEnabledUsers')) {
    try { $checkOnlyEnabledUsers = [System.Convert]::ToBoolean($ElysiumSettings['CheckOnlyEnabledUsers']) } catch { $checkOnlyEnabledUsers = $false }
}

# Function to get UPN for a given SAM account name
function Get-UserUPN {
    param (
        [string]$SamAccountName,
        [string]$Domain,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-Verbose "Attempting to get UPN for $SamAccountName in domain $Domain"
    try {
        # Remove domain prefix if exists
        $simplifiedSamAccountName = $SamAccountName -replace '^.*\\', ''
        
        $user = Get-ADUser -Identity $simplifiedSamAccountName -Properties UserPrincipalName -Server $Domain -Credential $Credential
        Write-Verbose "UPN found: $($user.UserPrincipalName)"
        return $user.UserPrincipalName
    } catch {
        Write-Verbose ("Failed to get UPN for {0}: {1}" -f $SamAccountName, $_.Exception.Message)
        return "UPN not found"
    }
}

# (removed stray top-level loop; UPN enrichment happens during report generation below)

function Resolve-DSInternalsWeakHashFile {
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Weak password hashes file not found at '$Path'."
    }

    $compatibleRegex = '^[0-9A-F]{32}$'
    $legacyRegex = '^[0-9A-Fa-f]{32}(:\d+)?$'
    $lineNumber = 0
    $previousHash = $null
    $duplicateCount = 0
    $legacyEntryCount = 0
    $needsNormalization = $false
    $reader = $null

    try {
        $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
        while (($line = $reader.ReadLine()) -ne $null) {
            $lineNumber++
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0) { continue }

            if ($trimmed -notmatch $legacyRegex) {
                throw ("Weak password hashes file '{0}' contains invalid content at line {1}: '{2}'." -f $Path, $lineNumber, $trimmed)
            }

            if ($trimmed -notmatch $compatibleRegex) {
                $needsNormalization = $true
                if ($trimmed.Contains(':')) { $legacyEntryCount++ }
            }

            $normalizedHash = ($trimmed.Split(':', 2)[0]).ToUpperInvariant()
            if ($line -cne $trimmed -or $trimmed -cne $normalizedHash) {
                $needsNormalization = $true
            }

            if ($null -ne $previousHash) {
                if ($normalizedHash -lt $previousHash) {
                    throw "Weak password hashes file '$Path' is not sorted alphabetically at line $lineNumber."
                }
                if ($normalizedHash -eq $previousHash) {
                    $duplicateCount++
                    $needsNormalization = $true
                }
            }

            $previousHash = $normalizedHash
        }
    } finally {
        if ($reader) { $reader.Dispose() }
    }

    if (-not $needsNormalization) {
        return [pscustomobject]@{
            Path        = $Path
            IsTemporary = $false
        }
    }

    $tmpPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('elysium-khdb-' + [System.Guid]::NewGuid().ToString() + '.txt'))
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $reader = $null
    $writer = $null
    $lastWrittenHash = $null

    try {
        $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
        $writer = New-Object System.IO.StreamWriter($tmpPath, $false, $encoding)

        while (($line = $reader.ReadLine()) -ne $null) {
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0) { continue }

            $normalizedHash = ($trimmed.Split(':', 2)[0]).ToUpperInvariant()
            if ($normalizedHash -eq $lastWrittenHash) { continue }

            $writer.WriteLine($normalizedHash)
            $lastWrittenHash = $normalizedHash
        }
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($writer) { $writer.Dispose() }
    }

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
function Test-WeakADPasswords {
    param (
        [hashtable]$DomainDetails,
        [string]$FilePath,
        [bool]$CheckOnlyEnabledUsers = $false,
        [System.Management.Automation.PSCredential]$Credential
    )

    # User selects a domain
    Write-Host "Select a domain to test:"
    $DomainDetails.GetEnumerator() | Sort-Object { [int]$_.Key } | ForEach-Object { Write-Host "$($_.Key): $($_.Value.Name)" }
    $selection = Read-Host "Enter the number of the domain"
    
    if (-not ($DomainDetails.ContainsKey($selection))) {
        Write-Error "Invalid selection."
        return
    }
    
    $selectedDomain = $DomainDetails[$selection]
    Write-Verbose "Selected domain: $($selectedDomain.Name)"

    if ([string]::IsNullOrWhiteSpace($selectedDomain["DC"])) {
        Write-Error ("Domain '{0}' does not have a configured DC in ElysiumSettings.txt." -f $selectedDomain.Name)
        return
    }

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
        $diagLines.Add('ELYSLUM DCSYNC DIAGNOSTIC DUMP')
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
            Write-Verbose "Looking up UPN for $samAccountName (dictionary hit)"
            $upn = Get-UserUPN -SamAccountName $samAccountName -Domain $selectedDomain.DC -Credential $credential
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
    } catch {
        Write-Error ("Failed to save report: {0}" -f $_.Exception.Message)
    }
}

# Main script logic
    Write-Verbose "Starting main script execution..."
    Test-WeakADPasswords -DomainDetails $domainDetails -FilePath $WeakHashesSortedFilePath -CheckOnlyEnabledUsers:$checkOnlyEnabledUsers
} catch {
    Write-Error ("An error occurred during script execution: {0}" -f $_.Exception.Message)
} finally {
    Stop-TestTranscript
}

Write-Host "Script execution completed."
