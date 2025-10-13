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
## Version: 1.3.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
#Requires -Modules DSInternals, ActiveDirectory
.SYNOPSIS
Weak AD password finder component of Elysium tool.

.DESCRIPTION
This script will test the passwords of selected domain (defined in ElysiumSettings.txt) using DSInternals' Test-PasswordQuality cmdlet. It writes its output to a report file which is meant to be shared with the internal security team. The report now includes UPNs for each account mentioned.
#>

# Enable verbose output
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$VerbosePreference = "Continue"

$scriptRoot = $PSScriptRoot

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
    # Import settings
    Write-Verbose "Loading settings..."
    $ElysiumSettings = @{}
    $settingsPath = Join-Path -Path $scriptRoot -ChildPath "ElysiumSettings.txt"

    # Ensure the settings file exists
    if (-not (Test-Path $settingsPath)) {
        Write-Error "Settings file not found at $settingsPath"
        exit
    }

    # Load settings from file
    try {
        Get-Content $settingsPath | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#")) {
                $keyValue = $_ -split '=', 2
                if ($keyValue.Count -eq 2) {
                    $ElysiumSettings[$keyValue[0].Trim()] = $keyValue[1].Trim()
                }
            }
        }
        Write-Verbose "Settings loaded successfully."
    } catch {
        Write-Error ("An error occurred while loading settings: {0}" -f $_.Exception.Message)
        exit
    }

# Define the function to extract domain details from settings
function Get-DomainDetailsFromSettings {
    param (
        [hashtable]$Settings
    )

    $domainDetails = @{}
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

if ($runningInPSCore -and -not $onWindows) {
    throw 'This script requires Windows when running under PowerShell 7 (AD/DSInternals are Windows-only).'
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
    Import-Module @params
    Write-Verbose ("Imported module '{0}' (Core={1}, Windows={2})" -f $Name, $runningInPSCore, $onWindows)
}

try { Import-CompatModule -Name 'ActiveDirectory' } catch { throw "Failed to import ActiveDirectory module. On PS7, ensure RSAT AD tools are installed and Windows PowerShell 5.1 is present. Details: $($_.Exception.Message)" }
try { Import-CompatModule -Name 'DSInternals' } catch { throw "Failed to import DSInternals module. On PS7, install DSInternals for Windows PowerShell (Install-Module DSInternals). Details: $($_.Exception.Message)" }

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

# Function to test for weak AD passwords
function Test-WeakADPasswords {
    param (
        [hashtable]$DomainDetails,
        [string]$FilePath,
        [bool]$CheckOnlyEnabledUsers = $false
    )

    # User selects a domain
    Write-Host "Select a domain to test:"
    $DomainDetails.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value.Name)" }
    $selection = Read-Host "Enter the number of the domain"
    
    if (-not ($DomainDetails.ContainsKey($selection))) {
        Write-Error "Invalid selection."
        return
    }
    
    $selectedDomain = $DomainDetails[$selection]
    Write-Verbose "Selected domain: $($selectedDomain.Name)"

    # Prompt for DA credentials
    $credential = Get-Credential -Message "Enter AD credentials with replication rights for $($selectedDomain.Name)"

    # Performing the test
    Write-Verbose "Testing password quality for $($selectedDomain.Name)..."
    try {
        $accounts = Get-ADReplAccount -All -Server $selectedDomain["DC"] -Credential $credential
        if ($CheckOnlyEnabledUsers) {
            Write-Verbose "Filtering to only enabled users per settings."
            # Prefer property 'Enabled' if present, fall back gracefully if not
            $accounts = $accounts | Where-Object {
                if ($_.PSObject.Properties.Name -contains 'Enabled') { $_.Enabled } else { $true }
            }
        }
        $testResults = $accounts | Test-PasswordQuality -WeakPasswordHashesFile $FilePath
        Write-Verbose "Password quality test completed."
    } catch {
        Write-Error ("An error occurred while testing passwords: {0}" -f $_.Exception.Message)
        return
    }

    # Report generation with dynamic content and UPNs
    $reportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_WeakPasswordReport_$timestamp.txt"
    $upnOnlyReportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_DictionaryPasswordUPNs_$timestamp.txt"
    
    Write-Verbose "Generating report at $reportPath"
    $reportContent = @($header, ($testResults | Out-String).Trim(), $footer) -join "`r`n"
    
    $lines = $reportContent -split "`r`n"
    $newReportContent = @()
    $upnReportContent = @()

    $collectingUPNs = $false

    foreach ($line in $lines) {
        $newReportContent += $line
        
        # Start collecting UPNs after detecting the relevant section in the report
        if ($line -match "Passwords of these accounts have been found in the dictionary:") {
            $collectingUPNs = $true
            continue
        }

        # Stop collecting UPNs if a new section starts or end of section is detected
        if ($collectingUPNs -and $line -match "^\s*$") {
            $collectingUPNs = $false
        }

        # Regex to match the SAMAccountName from the report line and collect UPNs if in the target section
        if ($collectingUPNs -and $line -match "^\s*(\S+)\s*$") {
            $samAccountName = $matches[1]
            Write-Verbose "Looking up UPN for $samAccountName"
            $upn = Get-UserUPN -SamAccountName $samAccountName -Domain $selectedDomain.DC -Credential $credential
            $newReportContent += "    UPN: $upn"

            # Collect UPNs only for accounts found in the dictionary section
            if ($upn -ne "UPN not found") {
                $upnReportContent += $upn
            }
        }
    }

    $updatedReportContent = $newReportContent -join "`r`n"
    $upnOnlyContent = $upnReportContent -join "`r`n"

    try {
        $updatedReportContent | Out-File -FilePath $reportPath -ErrorAction Stop
        Write-Host "Report saved to $reportPath"

        $upnOnlyContent | Out-File -FilePath $upnOnlyReportPath -ErrorAction Stop
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
